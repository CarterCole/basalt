//! S3-compatible transport, PROTOCOL §1.
//!
//! Works against AWS S3, MinIO and Cloudflare R2 with nothing but a flavor
//! change. The three disagree in ways that matter:
//!
//! - **Region.** R2 requires `auto`; MinIO ignores it; S3 enforces it.
//! - **Addressing.** MinIO and most self-hosted gateways need path-style
//!   (`host/bucket/key`); S3 and R2 prefer virtual-host style.
//! - **Checksums.** Newer AWS SDKs send integrity headers that R2 and older
//!   MinIO builds reject, so they are made opt-in here.
//! - **Etags.** A multipart upload's etag is not an MD5 of the content on any
//!   of them, and the formats differ. This is exactly why §10.1 records
//!   `content_hash` separately and treats *it* as authoritative.
//!
//! The AWS SDK is async and this trait is not, so the transport owns a current
//! -thread runtime and blocks on it. That keeps the indexer, the ACL engine
//! and the CLI free of an executor they have no use for, and the cost is
//! nothing: §1 asks for whole-object reads with no fan-out.

use super::{Capability, ListOpts, Listing, PutMeta, Result, Stat, Transport, TransportError};
use crate::keys::validate_key;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Flavor {
    S3,
    Minio,
    R2,
}

impl S3Flavor {
    pub fn parse(s: &str) -> Self {
        match s {
            "minio" => Self::Minio,
            "r2" => Self::R2,
            _ => Self::S3,
        }
    }

    fn default_region(self) -> &'static str {
        match self {
            // R2 presents one global endpoint and rejects a real region name.
            Self::R2 => "auto",
            _ => "us-east-1",
        }
    }

    fn force_path_style(self) -> bool {
        matches!(self, Self::Minio)
    }

    fn relax_checksums(self) -> bool {
        matches!(self, Self::Minio | Self::R2)
    }
}

#[derive(Debug, Clone, Default)]
pub struct S3Config {
    pub bucket: String,
    /// A key prefix within the bucket, e.g. `vaults/mine/`. Must end in `/`.
    pub prefix: String,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub flavor: Option<S3Flavor>,
    pub force_path_style: Option<bool>,
}

pub struct S3Transport {
    client: Client,
    runtime: tokio::runtime::Runtime,
    bucket: String,
    prefix: String,
    caps: BTreeSet<Capability>,
}

impl S3Transport {
    pub fn new(cfg: S3Config) -> Result<Self> {
        if cfg.bucket.is_empty() {
            return Err(TransportError::Backend(
                "S3Transport: bucket is required".into(),
            ));
        }
        if !cfg.prefix.is_empty() && !cfg.prefix.ends_with('/') {
            return Err(TransportError::Backend(
                "S3Transport: prefix must end in /".into(),
            ));
        }
        let flavor = cfg.flavor.unwrap_or(S3Flavor::S3);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| TransportError::Backend(format!("tokio runtime: {e}")))?;

        let region = cfg
            .region
            .clone()
            .unwrap_or_else(|| flavor.default_region().to_string());

        let client = runtime.block_on(async {
            let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_sdk_s3::config::Region::new(region));
            if let Some(ep) = &cfg.endpoint {
                loader = loader.endpoint_url(ep);
            }
            let shared = loader.load().await;
            let mut builder = aws_sdk_s3::config::Builder::from(&shared)
                .force_path_style(cfg.force_path_style.unwrap_or(flavor.force_path_style()));
            if flavor.relax_checksums() {
                // R2 and older MinIO reject the integrity headers newer SDKs
                // send by default; WhenRequired keeps them off unless the
                // operation genuinely needs them.
                builder = builder
                    .request_checksum_calculation(
                        aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
                    )
                    .response_checksum_validation(
                        aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
                    );
            }
            Client::from_conf(builder.build())
        });

        Ok(Self {
            client,
            runtime,
            bucket: cfg.bucket,
            prefix: cfg.prefix,
            caps: [
                Capability::Presign,
                Capability::ConditionalPut,
                Capability::RangeGet,
                Capability::BatchDelete,
            ]
            .into_iter()
            .collect(),
        })
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    fn strip(&self, full: &str) -> String {
        full.strip_prefix(self.prefix.as_str())
            .unwrap_or(full)
            .to_string()
    }
}

fn is_not_found<E: std::fmt::Debug, R>(err: &SdkError<E, R>) -> bool {
    match err {
        SdkError::ServiceError(e) => {
            format!("{:?}", e.err()).contains("NoSuchKey")
                || format!("{:?}", e.err()).contains("NotFound")
        }
        _ => false,
    }
}

impl Transport for S3Transport {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.runtime.block_on(async {
            match self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(self.key(key))
                .send()
                .await
            {
                Ok(out) => {
                    let body = out
                        .body
                        .collect()
                        .await
                        .map_err(|e| TransportError::Backend(format!("read body: {e}")))?;
                    Ok(Some(body.into_bytes().to_vec()))
                }
                Err(e) if is_not_found(&e) => Ok(None),
                Err(e) => Err(TransportError::Backend(format!("get {key}: {e}"))),
            }
        })
    }

    fn put(&self, key: &str, bytes: &[u8], meta: &PutMeta) -> Result<Stat> {
        validate_key(key)?;
        self.runtime.block_on(async {
            let mut req = self
                .client
                .put_object()
                .bucket(&self.bucket)
                .key(self.key(key))
                .body(ByteStream::from(bytes.to_vec()));
            if let Some(ct) = &meta.content_type {
                req = req.content_type(ct);
            }
            // §11.3: a conditional write turns a lost update into a visible
            // conflict. Without it, last-write-wins on a knowledge vault
            // silently destroys work.
            match &meta.if_match {
                Some(Some(etag)) => req = req.if_match(etag),
                Some(None) => req = req.if_none_match("*"),
                None => {}
            }
            match req.send().await {
                Ok(out) => Ok(Stat {
                    size: bytes.len() as u64,
                    etag: out.e_tag().map(str::to_string).or_else(|| {
                        Some(format!(
                            "\"{}\"",
                            crate::order::hex(&{
                                use md5::Digest as _;
                                md5::Md5::digest(bytes)
                            })
                        ))
                    }),
                    mtime: Some(crate::transport::fs::now_rfc3339()),
                }),
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("PreconditionFailed") || msg.contains("412") {
                        Err(TransportError::PreconditionFailed(key.to_string()))
                    } else {
                        Err(TransportError::Backend(format!("put {key}: {e}")))
                    }
                }
            }
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        // §1.2: S3's DeleteObject answers 204 whether or not the key was
        // there, and this transport reports exactly as much.
        self.runtime.block_on(async {
            match self
                .client
                .delete_object()
                .bucket(&self.bucket)
                .key(self.key(key))
                .send()
                .await
            {
                Ok(_) => Ok(()),
                Err(e) if is_not_found(&e) => Ok(()),
                Err(e) => Err(TransportError::Backend(format!("delete {key}: {e}"))),
            }
        })
    }

    fn list(&self, prefix: &str, opts: &ListOpts) -> Result<Listing> {
        self.runtime.block_on(async {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(self.key(prefix));
            if let Some(d) = opts.delimiter {
                req = req.delimiter(d.to_string());
            }
            if let Some(c) = &opts.cursor {
                req = req.continuation_token(c);
            }
            let out = req
                .send()
                .await
                .map_err(|e| TransportError::Backend(format!("list {prefix}: {e}")))?;
            Ok(Listing {
                keys: out
                    .contents()
                    .iter()
                    .filter_map(|c| c.key())
                    .map(|k| self.strip(k))
                    .collect(),
                prefixes: out
                    .common_prefixes()
                    .iter()
                    .filter_map(|p| p.prefix())
                    .map(|p| self.strip(p))
                    .collect(),
                // §1: `list` is paginated and eventually consistent, so the
                // cursor is handed back rather than looped over here.
                cursor: if out.is_truncated().unwrap_or(false) {
                    out.next_continuation_token().map(str::to_string)
                } else {
                    None
                },
            })
        })
    }

    fn stat(&self, key: &str) -> Result<Option<Stat>> {
        self.runtime.block_on(async {
            match self
                .client
                .head_object()
                .bucket(&self.bucket)
                .key(self.key(key))
                .send()
                .await
            {
                Ok(out) => Ok(Some(Stat {
                    size: out.content_length().unwrap_or(0).max(0) as u64,
                    etag: out.e_tag().map(str::to_string),
                    mtime: out
                        .last_modified()
                        .map(|t| crate::transport::fs::rfc3339(t.secs().max(0) as u64)),
                })),
                Err(e) if is_not_found(&e) => Ok(None),
                Err(e) => Err(TransportError::Backend(format!("stat {key}: {e}"))),
            }
        })
    }

    fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.caps
    }

    /// Mint a short-lived direct read URL (§12.4).
    ///
    /// A presigned URL is a bearer token that outlives the ACL check that
    /// produced it, which is why §12.4 caps the TTL and §15 names this as a
    /// standing hazard. The cap is enforced here rather than trusted to the
    /// caller, and §12.4 forbids presigning anything outside `content/`.
    fn presign(&self, key: &str, ttl_seconds: u64) -> Result<String> {
        if ttl_seconds > 300 {
            return Err(TransportError::Backend(
                "presign: §12.4 caps the TTL at 300s".into(),
            ));
        }
        if !key.starts_with(crate::keys::CONTENT) {
            return Err(TransportError::Backend(format!(
                "presign: §12.4 forbids presigning {key} — only content/ may be presigned"
            )));
        }
        self.runtime.block_on(async {
            let cfg = PresigningConfig::expires_in(Duration::from_secs(ttl_seconds))
                .map_err(|e| TransportError::Backend(format!("presign config: {e}")))?;
            let req = self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(self.key(key))
                .presigned(cfg)
                .await
                .map_err(|e| TransportError::Backend(format!("presign {key}: {e}")))?;
            Ok(req.uri().to_string())
        })
    }
}
