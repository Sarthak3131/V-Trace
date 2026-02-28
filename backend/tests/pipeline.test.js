'use strict';

/**
 * pipeline.test.js
 *
 * Jest test suite for the cryptographic chunk-hashing + Merkle-root pipeline.
 *
 * Covers:
 *  - generateChunkHashes output shape and format
 *  - buildMerkleRoot output format
 *  - Single-chunk identity rule (root === only chunk hash)
 *  - Multi-chunk determinism and structural correctness
 *  - Edge cases: empty file, exact chunk boundary, input validation errors
 *
 * Uses only Node.js built-in modules alongside Jest.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { createHash } = require('crypto');
const { generateChunkHashes } = require('../src/core/generateChunkHashes');
const { buildMerkleRoot } = require('../src/core/merkle');

// ─── Shared constants ──────────────────────────────────────────────────────────

const SHA256_HEX_RE  = /^[0-9a-f]{64}$/;
const SMALL_CHUNK    = 64;          // 64 bytes — makes multi-chunk tests easy
const TMP_DIR        = os.tmpdir();

// ─── Utility helpers ───────────────────────────────────────────────────────────

/**
 * Creates a temporary file with deterministic content and returns its path.
 * @param {string} name     - Filename suffix (for readability in errors).
 * @param {Buffer} content  - File contents.
 * @returns {string} Absolute path to the created file.
 */
function createTmpFile(name, content) {
  const filePath = path.join(TMP_DIR, `merkle_test_${name}_${Date.now()}`);
  fs.writeFileSync(filePath, content);
  return filePath;
}

/**
 * Removes a file, silently ignoring "not found" errors.
 * @param {string} filePath
 */
function removeTmpFile(filePath) {
  try { fs.unlinkSync(filePath); } catch { /* already gone */ }
}

/**
 * Computes the SHA-256 hex hash of a Buffer (used for expected-value checks).
 * @param {Buffer} buf
 * @returns {string}
 */
function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

// ─── Test suite ────────────────────────────────────────────────────────────────

describe('Cryptographic pipeline: generateChunkHashes + buildMerkleRoot', () => {

  // ── generateChunkHashes ──────────────────────────────────────────────────────

  describe('generateChunkHashes()', () => {
    describe('output shape', () => {
      let filePath;
      let chunkHashes;

      beforeAll(async () => {
        // 3 full chunks + 1 partial chunk  →  4 hashes expected
        const content = Buffer.alloc(SMALL_CHUNK * 3 + 10, 0x61); // 'aaa…'
        filePath    = createTmpFile('shape', content);
        chunkHashes = await generateChunkHashes(filePath, SMALL_CHUNK);
      });

      afterAll(() => removeTmpFile(filePath));

      it('returns an Array', () => {
        expect(Array.isArray(chunkHashes)).toBe(true);
      });

      it('returns the correct number of chunks', () => {
        expect(chunkHashes).toHaveLength(4);
      });

      it('every element is a 64-character lowercase hex string', () => {
        for (const hash of chunkHashes) {
          expect(hash).toMatch(SHA256_HEX_RE);
        }
      });
    });

    describe('single-chunk file', () => {
      let filePath;
      let chunkHashes;
      const content = Buffer.from('Hello, Merkle!');

      beforeAll(async () => {
        filePath    = createTmpFile('single', content);
        // chunkSize larger than file  →  entire file is one chunk
        chunkHashes = await generateChunkHashes(filePath, 1024);
      });

      afterAll(() => removeTmpFile(filePath));

      it('returns exactly one hash', () => {
        expect(chunkHashes).toHaveLength(1);
      });

      it('the hash matches SHA-256 of the full file content', () => {
        expect(chunkHashes[0]).toBe(sha256hex(content));
      });
    });

    describe('exact chunk-boundary file', () => {
      let filePath;
      let chunkHashes;

      beforeAll(async () => {
        const content = Buffer.alloc(SMALL_CHUNK * 4, 0x42); // exactly 4 chunks
        filePath    = createTmpFile('boundary', content);
        chunkHashes = await generateChunkHashes(filePath, SMALL_CHUNK);
      });

      afterAll(() => removeTmpFile(filePath));

      it('produces exactly 4 hashes with no phantom extra chunk', () => {
        expect(chunkHashes).toHaveLength(4);
      });

      it('each chunk hash equals SHA-256 of that chunk slice', () => {
        const raw = fs.readFileSync(filePath);
        for (let i = 0; i < 4; i++) {
          const slice    = raw.slice(i * SMALL_CHUNK, (i + 1) * SMALL_CHUNK);
          const expected = sha256hex(slice);
          expect(chunkHashes[i]).toBe(expected);
        }
      });
    });

    describe('empty file', () => {
      let filePath;

      beforeAll(() => { filePath = createTmpFile('empty', Buffer.alloc(0)); });
      afterAll(() => removeTmpFile(filePath));

      it('returns an empty array for a zero-byte file', async () => {
        const hashes = await generateChunkHashes(filePath, SMALL_CHUNK);
        expect(hashes).toEqual([]);
      });
    });

    describe('determinism', () => {
      let filePath;

      beforeAll(() => {
        const content = Buffer.from('Deterministic content for hashing');
        filePath = createTmpFile('det', content);
      });

      afterAll(() => removeTmpFile(filePath));

      it('returns the same hashes on repeated calls', async () => {
        const first  = await generateChunkHashes(filePath, SMALL_CHUNK);
        const second = await generateChunkHashes(filePath, SMALL_CHUNK);
        expect(first).toEqual(second);
      });
    });

    describe('input validation', () => {
      it('throws TypeError for non-string filePath', async () => {
        await expect(generateChunkHashes(42)).rejects.toThrow(TypeError);
      });

      it('throws TypeError for empty-string filePath', async () => {
        await expect(generateChunkHashes('   ')).rejects.toThrow(TypeError);
      });

      it('throws RangeError for non-positive chunkSize', async () => {
        await expect(generateChunkHashes('/tmp/x', 0)).rejects.toThrow(RangeError);
      });

      it('rejects when the file does not exist', async () => {
        await expect(
          generateChunkHashes('/nonexistent/path/file.bin', SMALL_CHUNK)
        ).rejects.toThrow();
      });
    });
  });

  // ── buildMerkleRoot ──────────────────────────────────────────────────────────

  describe('buildMerkleRoot()', () => {
    describe('output format', () => {
      let filePath;
      let root;

      beforeAll(async () => {
        const content = Buffer.alloc(SMALL_CHUNK * 5 + 33, 0x7a);
        filePath      = createTmpFile('rootfmt', content);
        const hashes  = await generateChunkHashes(filePath, SMALL_CHUNK);
        root          = buildMerkleRoot(hashes);
      });

      afterAll(() => removeTmpFile(filePath));

      it('returns a string', () => {
        expect(typeof root).toBe('string');
      });

      it('is a 64-character lowercase hex string', () => {
        expect(root).toMatch(SHA256_HEX_RE);
      });
    });

    describe('single-chunk identity rule', () => {
      let filePath;
      let chunkHashes;
      let root;

      beforeAll(async () => {
        const content = Buffer.from('Only one chunk here');
        filePath      = createTmpFile('identity', content);
        chunkHashes   = await generateChunkHashes(filePath, 1024);
        root          = buildMerkleRoot(chunkHashes);
      });

      afterAll(() => removeTmpFile(filePath));

      it('Merkle root equals the single chunk hash', () => {
        expect(chunkHashes).toHaveLength(1);
        expect(root).toBe(chunkHashes[0]);
      });
    });

    describe('multi-chunk determinism', () => {
      let filePath;

      beforeAll(() => {
        const content = Buffer.alloc(SMALL_CHUNK * 3 + 17, 0x55);
        filePath      = createTmpFile('multidet', content);
      });

      afterAll(() => removeTmpFile(filePath));

      it('produces the same root on repeated calls', async () => {
        const hashes = await generateChunkHashes(filePath, SMALL_CHUNK);
        const root1  = buildMerkleRoot(hashes);
        const root2  = buildMerkleRoot([...hashes]); // copy — must not mutate
        expect(root1).toBe(root2);
      });
    });

    describe('full end-to-end pipeline', () => {
      let filePath;
      let chunkHashes;
      let root;

      beforeAll(async () => {
        // 4 full chunks — even count, so no odd-duplication needed.
        const content = Buffer.alloc(SMALL_CHUNK * 4, 0x30);
        filePath      = createTmpFile('e2e', content);
        chunkHashes   = await generateChunkHashes(filePath, SMALL_CHUNK);
        root          = buildMerkleRoot(chunkHashes);
      });

      afterAll(() => removeTmpFile(filePath));

      it('chunkHashes is an array of 64-char hex strings', () => {
        expect(Array.isArray(chunkHashes)).toBe(true);
        for (const h of chunkHashes) expect(h).toMatch(SHA256_HEX_RE);
      });

      it('Merkle root is a 64-character hex string', () => {
        expect(root).toMatch(SHA256_HEX_RE);
      });

      it('root is distinct from every individual chunk hash (multi-chunk)', () => {
        for (const h of chunkHashes) expect(root).not.toBe(h);
      });
    });

    describe('odd number of chunks (duplication rule)', () => {
      let filePath;
      let chunkHashes;
      let root;

      beforeAll(async () => {
        // 3 chunks — odd, so last is duplicated when building parent level.
        const content = Buffer.alloc(SMALL_CHUNK * 3, 0x11);
        filePath      = createTmpFile('odd', content);
        chunkHashes   = await generateChunkHashes(filePath, SMALL_CHUNK);
        root          = buildMerkleRoot(chunkHashes);
      });

      afterAll(() => removeTmpFile(filePath));

      it('still returns a 64-char hex root despite odd leaf count', () => {
        expect(chunkHashes).toHaveLength(3);
        expect(root).toMatch(SHA256_HEX_RE);
      });
    });

    describe('buildMerkleRoot input validation', () => {
      it('throws TypeError when passed a non-array', () => {
        expect(() => buildMerkleRoot('not an array')).toThrow(TypeError);
      });

      it('throws RangeError when passed an empty array', () => {
        expect(() => buildMerkleRoot([])).toThrow(RangeError);
      });

      it('throws TypeError when an element is not a valid hex string', () => {
        expect(() => buildMerkleRoot(['ZZZZ'])).toThrow(TypeError);
      });

      it('throws TypeError when an element is too short', () => {
        expect(() => buildMerkleRoot(['abc123'])).toThrow(TypeError);
      });
    });
  });
});