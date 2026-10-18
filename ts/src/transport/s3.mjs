// S3-compatible transport, PROTOCOL §1. Works against AWS S3, MinIO and
// Cloudflare R2 with nothing but an endpoint change.
//
// The AWS SDK is imported lazily so that the core protocol — indexing, link
// resolution, ACL evaluation — runs with no cloud dependency installed at all.

import { createHash } from 'node:crypto';
import { validateKey } from '../keys.mjs';

/**
 * The three stores this targets disagree in ways that matter:
 *
 * - **Region.** R2 requires `auto`; MinIO ignores it; S3 enforces it.
 * - **Addressing.** MinIO and most self-hosted gateways need path-style
 *   (`host/bucket/key`); S3 and R2 prefer virtual-host style.
 * - **Checksums.** Newer AWS SDKs add integrity headers that R2 and older
 *   MinIO builds reject, so they are made opt-in here.
 * - **Etags.** A multipart upload's etag is not an MD5 of the content on any
 *   of them, and the formats differ. This is exactly why §10.1 records
 *   `content_hash` separately and treats *it* as authoritative.
 */
const PRESETS = {
  s3: {},
  minio: { forcePathStyle: true, region: 'us-east-1', relaxChecksums: true },
  r2: { region: 'auto', relaxChecksums: true },
};

export class S3Transport {
  /**
   * @param {object} opts
   * @param {string} opts.bucket
   * @param {string} [opts.prefix] key prefix within the bucket, e.g. "vaults/mine/"
   * @param {string} [opts.endpoint] required for MinIO and R2
   * @param {'s3'|'minio'|'r2'} [opts.flavor]
   */
  constructor({ bucket, prefix = '', endpoint, region, flavor = 's3',
                accessKeyId, secretAccessKey, forcePathStyle } = {}) {
    if (!bucket) throw new Error('S3Transport: bucket is required');
    if (prefix && !prefix.endsWith('/')) throw new Error('S3Transport: prefix must end in /');

    const preset = PRESETS[flavor] ?? {};
    this.bucket = bucket;
    this.prefix = prefix;
    this.flavor = flavor;
    this.relaxChecksums = preset.relaxChecksums ?? false;
    this.config = {
      region: region ?? preset.region ?? 'us-east-1',
      forcePathStyle: forcePathStyle ?? preset.forcePathStyle ?? false,
      ...(endpoint ? { endpoint } : {}),
      ...(accessKeyId && secretAccessKey
        ? { credentials: { accessKeyId, secretAccessKey } }
        : {}),
    };
    this.capabilities = new Set(['presign', 'conditional_put', 'range_get', 'batch_delete']);
    this.#client = null;
    this.#sdk = null;
  }

  #client;
  #sdk;

  async #load() {
    if (this.#client) return this.#sdk;
    let sdk;
    try {
      sdk = await import('@aws-sdk/client-s3');
    } catch {
      throw new Error(
        'S3Transport needs @aws-sdk/client-s3. Install it, or use FsTransport ' +
        'for a local vault.',
      );
    }
    const cfg = { ...this.config };
    if (this.relaxChecksums) {
      // R2 and older MinIO reject the integrity headers newer SDKs send by
      // default; "WHEN_REQUIRED" keeps them off unless the operation needs them.
      cfg.requestChecksumCalculation = 'WHEN_REQUIRED';
      cfg.responseChecksumValidation = 'WHEN_REQUIRED';
    }
    this.#client = new sdk.S3Client(cfg);
    this.#sdk = sdk;
    return sdk;
  }

  #key(key) { return this.prefix + key; }
  #strip(full) { return full.slice(this.prefix.length); }

  async get(key) {
    const sdk = await this.#load();
    try {
      const out = await this.#client.send(new sdk.GetObjectCommand({
        Bucket: this.bucket, Key: this.#key(key),
      }));
      return Buffer.from(await out.Body.transformToByteArray());
    } catch (err) {
      if (isNotFound(err)) return null;
      throw err;
    }
  }

  async put(key, bytes, { ifMatch, contentType } = {}) {
    validateKey(key);
    const sdk = await this.#load();
    const body = Buffer.from(bytes);
    const params = {
      Bucket: this.bucket, Key: this.#key(key), Body: body,
      ...(contentType ? { ContentType: contentType } : {}),
    };
    // §11.3: conditional writes turn a lost update into a visible conflict.
    if (ifMatch !== undefined) {
      if (ifMatch === null) params.IfNoneMatch = '*';
      else params.IfMatch = ifMatch;
    }
    try {
      const out = await this.#client.send(new sdk.PutObjectCommand(params));
      return {
        size: body.length,
        etag: out.ETag ?? `"${createHash('md5').update(body).digest('hex')}"`,
        mtime: new Date().toISOString(),
      };
    } catch (err) {
      if (err?.name === 'PreconditionFailed' || err?.$metadata?.httpStatusCode === 412) {
        const e = new Error(`precondition failed for ${key}`);
        e.code = 'PRECONDITION_FAILED';
        throw e;
      }
      throw err;
    }
  }

  async delete(key) {
    // §1.2: DeleteObject answers 204 whether or not the key existed, so there
    // is nothing truthful to return.
    const sdk = await this.#load();
    try {
      await this.#client.send(new sdk.DeleteObjectCommand({
        Bucket: this.bucket, Key: this.#key(key),
      }));
    } catch (err) {
      if (!isNotFound(err)) throw err;
    }
  }

  async stat(key) {
    const sdk = await this.#load();
    try {
      const out = await this.#client.send(new sdk.HeadObjectCommand({
        Bucket: this.bucket, Key: this.#key(key),
      }));
      return {
        size: out.ContentLength ?? 0,
        etag: out.ETag ?? null,
        mtime: (out.LastModified ?? new Date()).toISOString(),
      };
    } catch (err) {
      if (isNotFound(err)) return null;
      throw err;
    }
  }

  async list(prefix = '', { delimiter, cursor } = {}) {
    const sdk = await this.#load();
    const keys = [];
    const prefixes = [];
    let token = cursor;
    do {
      const out = await this.#client.send(new sdk.ListObjectsV2Command({
        Bucket: this.bucket,
        Prefix: this.#key(prefix),
        ...(delimiter ? { Delimiter: delimiter } : {}),
        ...(token ? { ContinuationToken: token } : {}),
      }));
      for (const c of out.Contents ?? []) keys.push(this.#strip(c.Key));
      for (const p of out.CommonPrefixes ?? []) prefixes.push(this.#strip(p.Prefix));
      token = out.IsTruncated ? out.NextContinuationToken : undefined;
    } while (token);
    return { keys, prefixes };
  }

  /**
   * Mint a short-lived direct read URL (§12.4).
   *
   * A presigned URL is a bearer token that outlives the ACL check that
   * produced it, which is why §12.4 caps the TTL and §15 names this as a
   * standing hazard. Never presign anything outside content/.
   */
  async presign(key, { ttlSeconds = 300 } = {}) {
    if (ttlSeconds > 300) throw new Error('presign: §12.4 caps TTL at 300s');
    const sdk = await this.#load();
    let signer;
    try {
      signer = await import('@aws-sdk/s3-request-presigner');
    } catch {
      throw new Error('presign needs @aws-sdk/s3-request-presigner');
    }
    return signer.getSignedUrl(
      this.#client,
      new sdk.GetObjectCommand({ Bucket: this.bucket, Key: this.#key(key) }),
      { expiresIn: ttlSeconds },
    );
  }
}

function isNotFound(err) {
  const s = err?.$metadata?.httpStatusCode;
  return s === 404 || err?.name === 'NoSuchKey' || err?.name === 'NotFound';
}
