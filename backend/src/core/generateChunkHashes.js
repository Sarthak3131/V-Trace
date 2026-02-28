'use strict';

/**
 * generateChunkHashes.js
 *
 * Reads a file in fixed-size chunks and returns a SHA-256 hex hash
 * for each chunk. Uses only Node.js built-in modules.
 */

const fs   = require('fs');
const path = require('path');
const { createHash } = require('crypto');

/** Default chunk size: 1 MiB */
const DEFAULT_CHUNK_SIZE = 1024 * 1024;

/**
 * Reads `filePath` in sequential chunks of `chunkSize` bytes and returns
 * an array of SHA-256 hex strings — one per chunk.
 *
 * @param {string} filePath   - Absolute or relative path to the file.
 * @param {number} [chunkSize=1048576] - Bytes per chunk (default 1 MiB).
 * @returns {Promise<string[]>} Resolves with an array of 64-char hex strings.
 *
 * @throws {TypeError}  If filePath is not a non-empty string.
 * @throws {RangeError} If chunkSize is not a positive integer.
 * @throws {Error}      If the file cannot be opened or read.
 */
async function generateChunkHashes(filePath, chunkSize = DEFAULT_CHUNK_SIZE) {
  // ── Input validation ────────────────────────────────────────────────────────
  if (typeof filePath !== 'string' || filePath.trim() === '') {
    throw new TypeError('generateChunkHashes: filePath must be a non-empty string');
  }
  if (!Number.isInteger(chunkSize) || chunkSize <= 0) {
    throw new RangeError('generateChunkHashes: chunkSize must be a positive integer');
  }

  const resolvedPath = path.resolve(filePath);

  return new Promise((resolve, reject) => {
    const hashes = [];
    let currentHash = createHash('sha256');
    let bytesInCurrentChunk = 0;

    const stream = fs.createReadStream(resolvedPath, { highWaterMark: chunkSize });

    stream.on('error', (err) => reject(err));

    stream.on('data', (chunk) => {
      // A single 'data' event may deliver less than chunkSize bytes when the
      // stream's internal buffer is smaller. We process byte-by-byte slicing
      // to honour the exact chunkSize boundary.
      let offset = 0;

      while (offset < chunk.length) {
        const remaining  = chunkSize - bytesInCurrentChunk;
        const slice      = chunk.slice(offset, offset + remaining);

        currentHash.update(slice);
        bytesInCurrentChunk += slice.length;
        offset              += slice.length;

        if (bytesInCurrentChunk === chunkSize) {
          hashes.push(currentHash.digest('hex'));
          currentHash        = createHash('sha256');
          bytesInCurrentChunk = 0;
        }
      }
    });

    stream.on('end', () => {
      // Flush any remaining bytes as the final (possibly smaller) chunk.
      if (bytesInCurrentChunk > 0) {
        hashes.push(currentHash.digest('hex'));
      }
      resolve(hashes);
    });
  });
}

module.exports = { generateChunkHashes };