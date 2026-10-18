"""S3-compatible transport, PROTOCOL §1.

Works against AWS S3, MinIO and Cloudflare R2 with nothing but an endpoint
change, because the protocol builds over the intersection of what S3-like
stores agree on (§1) rather than the union.

``boto3`` is imported lazily so that the core protocol — indexing, link
resolution, ACL evaluation — runs with no cloud dependency installed at all.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

from ..keys import validate_key
from . import UNSET, Listing, PreconditionFailed, Stat, Transport

#: The three stores this targets disagree in ways that matter:
#:
#: - **Region.** R2 requires ``auto``; MinIO ignores it; S3 enforces it.
#: - **Addressing.** MinIO and most self-hosted gateways need path-style
#:   (``host/bucket/key``); S3 and R2 prefer virtual-host style.
#: - **Checksums.** Newer AWS SDKs add integrity headers that R2 and older
#:   MinIO builds reject, so they are made opt-in here.
#: - **Etags.** A multipart upload's etag is not an MD5 of the content on any
#:   of them, and the formats differ. This is exactly why §10.1 records
#:   ``content_hash`` separately and treats *it* as authoritative.
PRESETS: dict[str, dict[str, Any]] = {
    "s3": {},
    "minio": {
        "force_path_style": True,
        "region": "us-east-1",
        "relax_checksums": True,
    },
    "r2": {"region": "auto", "relax_checksums": True},
}


class S3Transport(Transport):
    """A vault in an S3-compatible bucket, optionally under a key prefix."""

    capabilities = frozenset(
        {"presign", "conditional_put", "range_get", "batch_delete"}
    )

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        endpoint: str | None = None,
        region: str | None = None,
        flavor: str = "s3",
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        force_path_style: bool | None = None,
    ) -> None:
        if not bucket:
            raise ValueError("S3Transport: bucket is required")
        if prefix and not prefix.endswith("/"):
            raise ValueError("S3Transport: prefix must end in /")

        preset = PRESETS.get(flavor, {})
        self.bucket = bucket
        self.prefix = prefix
        self.flavor = flavor
        self.endpoint = endpoint
        self.region = region or preset.get("region") or "us-east-1"
        self.force_path_style = (
            force_path_style
            if force_path_style is not None
            else bool(preset.get("force_path_style", False))
        )
        self.relax_checksums = bool(preset.get("relax_checksums", False))
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._client: Any = None

    # ------------------------------------------------------------ client

    def _load(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3
            from botocore.config import Config
        except ImportError as err:  # pragma: no cover - import-time only
            raise RuntimeError(
                "S3Transport needs boto3. Install it (pip install "
                "'basalt-protocol[s3]'), or use LocalTransport for a local vault."
            ) from err

        cfg: dict[str, Any] = {"signature_version": "s3v4"}
        if self.force_path_style:
            cfg["s3"] = {"addressing_style": "path"}
        if self.relax_checksums:
            # R2 and older MinIO reject the integrity headers newer SDKs send
            # by default; "when_required" keeps them off unless the operation
            # needs them. Older botocore does not know these knobs, so the
            # config is built without them rather than failing outright.
            cfg["request_checksum_calculation"] = "when_required"
            cfg["response_checksum_validation"] = "when_required"
        try:
            config = Config(**cfg)
        except TypeError:
            cfg.pop("request_checksum_calculation", None)
            cfg.pop("response_checksum_validation", None)
            config = Config(**cfg)

        kwargs: dict[str, Any] = {"region_name": self.region, "config": config}
        if self.endpoint:
            kwargs["endpoint_url"] = self.endpoint
        if self._access_key_id and self._secret_access_key:
            kwargs["aws_access_key_id"] = self._access_key_id
            kwargs["aws_secret_access_key"] = self._secret_access_key

        self._client = boto3.client("s3", **kwargs)
        return self._client

    def _full(self, key: str) -> str:
        return self.prefix + key

    def _strip(self, full: str) -> str:
        return full[len(self.prefix) :]

    # ------------------------------------------------------------- reads

    def get(self, key: str) -> bytes | None:
        client = self._load()
        try:
            out = client.get_object(Bucket=self.bucket, Key=self._full(key))
        except Exception as err:  # normalized below
            if _is_not_found(err):
                return None
            raise
        return out["Body"].read()

    def stat(self, key: str) -> Stat | None:
        client = self._load()
        try:
            out = client.head_object(Bucket=self.bucket, Key=self._full(key))
        except Exception as err:  # normalized below
            if _is_not_found(err):
                return None
            raise
        modified = out.get("LastModified")
        return Stat(
            size=int(out.get("ContentLength") or 0),
            etag=out.get("ETag"),
            mtime=_iso(modified),
        )

    def list(
        self,
        prefix: str = "",
        *,
        delimiter: str | None = None,
        cursor: str | None = None,
    ) -> Listing:
        client = self._load()
        keys: list[str] = []
        prefixes: list[str] = []
        token = cursor
        while True:
            params: dict[str, Any] = {
                "Bucket": self.bucket,
                "Prefix": self._full(prefix),
            }
            if delimiter:
                params["Delimiter"] = delimiter
            if token:
                params["ContinuationToken"] = token
            out = client.list_objects_v2(**params)
            for c in out.get("Contents") or []:
                keys.append(self._strip(c["Key"]))
            for p in out.get("CommonPrefixes") or []:
                prefixes.append(self._strip(p["Prefix"]))
            if not out.get("IsTruncated"):
                break
            token = out.get("NextContinuationToken")
            if not token:
                break
        return Listing(keys=keys, prefixes=prefixes)

    # ------------------------------------------------------------ writes

    def put(
        self,
        key: str,
        data: bytes,
        *,
        if_match: Any = UNSET,
        content_type: str | None = None,
    ) -> Stat:
        validate_key(key)
        client = self._load()
        body = bytes(data)
        params: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": self._full(key),
            "Body": body,
        }
        if content_type:
            params["ContentType"] = content_type
        # §11.3: conditional writes turn a lost update into a visible conflict.
        if if_match is not UNSET:
            if if_match is None:
                params["IfNoneMatch"] = "*"
            else:
                params["IfMatch"] = if_match
        try:
            out = client.put_object(**params)
        except Exception as err:  # normalized below
            if _is_precondition_failed(err):
                raise PreconditionFailed(f"precondition failed for {key!r}") from err
            raise
        digest = hashlib.md5(body, usedforsecurity=False).hexdigest()
        return Stat(
            size=len(body),
            etag=out.get("ETag") or f'"{digest}"',
            mtime=_iso(dt.datetime.now(dt.UTC)),
        )

    def delete(self, key: str) -> bool:
        client = self._load()
        try:
            client.delete_object(Bucket=self.bucket, Key=self._full(key))
        except Exception as err:  # normalized below
            if _is_not_found(err):
                return False
            raise
        return True

    # --------------------------------------------------------- optional

    def presign(self, key: str, *, ttl_seconds: int = 300) -> str:
        """Mint a short-lived direct read URL (§12.4).

        A presigned URL is a bearer token that outlives the ACL check that
        produced it, which is why §12.4 caps the TTL and §15 names this as a
        standing hazard. Never presign anything outside ``content/``.
        """
        if ttl_seconds > 300:
            raise ValueError("presign: §12.4 caps TTL at 300s")
        client = self._load()
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": self._full(key)},
            ExpiresIn=ttl_seconds,
        )


def _status(err: Exception) -> int | None:
    meta = getattr(err, "response", None)
    if isinstance(meta, dict):
        code = meta.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if isinstance(code, int):
            return code
    return None


def _error_code(err: Exception) -> str:
    meta = getattr(err, "response", None)
    if isinstance(meta, dict):
        return str(meta.get("Error", {}).get("Code", ""))
    return ""


def _is_not_found(err: Exception) -> bool:
    return _status(err) == 404 or _error_code(err) in ("NoSuchKey", "NotFound", "404")


def _is_precondition_failed(err: Exception) -> bool:
    return _status(err) == 412 or _error_code(err) == "PreconditionFailed"


def _iso(value: Any) -> str | None:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.UTC)
        return value.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")
    return None


__all__ = ["PRESETS", "S3Transport"]
