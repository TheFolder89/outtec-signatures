import { DeleteObjectCommand, GetObjectCommand, HeadObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { Readable } from "node:stream";
import type { EnvSource } from "../../utils/env.ts";
import { assertServiceConfig } from "../service-config.ts";
import { normalizeStorageKey, StorageObjectNotFoundError, type StorageService } from "./types.ts";

export function createR2StorageService({ env = process.env }: { env?: EnvSource } = {}): StorageService {
  assertServiceConfig("R2", ["R2_ENDPOINT", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET"], env);
  const endpoint = new URL(env.R2_ENDPOINT!);
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || !endpoint.hostname.endsWith(".r2.cloudflarestorage.com")) throw new Error("R2 requires the configured Cloudflare HTTPS endpoint.");
  const bucketName = env.R2_BUCKET!, prefix = "signature-engine/";
  const client = new S3Client({ endpoint: endpoint.toString(), region: "auto", forcePathStyle: true, credentials: { accessKeyId: env.R2_ACCESS_KEY_ID!, secretAccessKey: env.R2_SECRET_ACCESS_KEY! } });
  const ref = (key: string) => ({ bucketName, key: normalizeStorageKey(key) });
  const command = (key: string) => ({ Bucket: bucketName, Key: prefix + normalizeStorageKey(key) });
  const missing = (error: unknown) => (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 404;
  return {
    async putObject(input) {
      if (!input.body.length || input.body.length > 25_000_000) throw new Error("R2 signature object exceeds the limit.");
      try { await client.send(new PutObjectCommand({ ...command(input.key), Body: input.body, ContentLength: input.body.length, ContentType: input.contentType, CacheControl: "private, no-store", ...(input.keepExisting ? { IfNoneMatch: "*" } : {}) }), { abortSignal: AbortSignal.timeout(12000) }); }
      catch (error) { if (!input.keepExisting || (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode !== 412) throw error; }
      return ref(input.key);
    },
    async getObject(key) {
      try {
        const response = await client.send(new GetObjectCommand(command(key)), { abortSignal: AbortSignal.timeout(12000) });
        if (!response.Body || (response.ContentLength ?? 0) > 25_000_000) throw new Error("R2 signature object unavailable.");
        const chunks: Uint8Array[] = []; let length = 0;
        for await (const chunk of response.Body as AsyncIterable<Uint8Array>) { length += chunk.length; if (length > 25_000_000) throw new Error("R2 signature object exceeds the limit."); chunks.push(chunk); }
        return { ...ref(key), body: Buffer.concat(chunks), contentLength: length, contentType: response.ContentType, etag: response.ETag };
      } catch (error) { if (missing(error)) throw new StorageObjectNotFoundError(key); throw error; }
    },
    async getObjectStream(key) {
      try {
        const response = await client.send(new GetObjectCommand(command(key)), { abortSignal: AbortSignal.timeout(12000) });
        if (!response.Body) throw new StorageObjectNotFoundError(key);
        return { ...ref(key), stream: Readable.toWeb(response.Body as Readable) as ReadableStream<Uint8Array>, contentLength: response.ContentLength, contentType: response.ContentType, etag: response.ETag };
      } catch (error) { if (missing(error)) throw new StorageObjectNotFoundError(key); throw error; }
    },
    async headObject(key) {
      try { const response = await client.send(new HeadObjectCommand(command(key)), { abortSignal: AbortSignal.timeout(12000) }); return { ...ref(key), exists: true, contentLength: response.ContentLength, contentType: response.ContentType, etag: response.ETag }; }
      catch (error) { if (missing(error)) return { ...ref(key), exists: false }; throw error; }
    },
    async deleteObject(key) { await client.send(new DeleteObjectCommand(command(key)), { abortSignal: AbortSignal.timeout(12000) }); },
  };
}
