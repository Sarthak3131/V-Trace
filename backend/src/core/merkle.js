'use strict';

/**
 * merkle.js
 * Production-ready Merkle Tree builder using Node.js built-in crypto.
 * No external dependencies required.
 */

const { createHash } = require('crypto');

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Validates that a value is a 64-character lowercase hex string (SHA-256 hash).
 * @param {string} hash
 * @returns {boolean}
 */
function isValidSHA256Hex(hash) {
  return typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash);
}

/**
 * Computes SHA-256 of the concatenation of two hex strings and returns
 * the result as a lowercase hex string.
 *
 * @param {string} leftHex  - Left child hash (hex string).
 * @param {string} rightHex - Right child hash (hex string).
 * @returns {string} Parent hash (hex string).
 */
function hashPair(leftHex, rightHex) {
  const leftBuffer  = Buffer.from(leftHex, 'hex');
  const rightBuffer = Buffer.from(rightHex, 'hex');

  return createHash('sha256')
    .update(Buffer.concat([leftBuffer, rightBuffer]))
    .digest('hex');
}

/**
 * Builds one level of the Merkle Tree from an array of hashes.
 * If the level has an odd number of nodes the last node is duplicated.
 *
 * @param {string[]} level - Current level hashes.
 * @returns {string[]}     - Next (parent) level hashes.
 */
function buildNextLevel(level) {
  // Duplicate last node when the count is odd (Bitcoin-style).
  const nodes = level.length % 2 === 0 ? level : [...level, level[level.length - 1]];

  const parent = [];
  for (let i = 0; i < nodes.length; i += 2) {
    parent.push(hashPair(nodes[i], nodes[i + 1]));
  }
  return parent;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Builds a Merkle Tree from an array of SHA-256 hex strings and returns
 * the Merkle Root as a lowercase hex string.
 *
 * Rules:
 *  - Input hashes are the leaves (bottom level) of the tree.
 *  - At every level, pairs of nodes are concatenated (left + right) and
 *    hashed with SHA-256 to produce the parent node.
 *  - If a level contains an odd number of nodes the last node is duplicated
 *    before pairing.
 *  - The process repeats until a single root hash remains.
 *
 * @param {string[]} hashes - Non-empty array of SHA-256 hex strings.
 * @returns {string}          Merkle root as a lowercase hex string.
 *
 * @throws {TypeError}  If `hashes` is not an array or contains invalid entries.
 * @throws {RangeError} If `hashes` is empty.
 *
 * @example
 * const { buildMerkleRoot } = require('./merkle');
 *
 * const root = buildMerkleRoot([
 *   'a'.repeat(64),
 *   'b'.repeat(64),
 *   'c'.repeat(64),
 * ]);
 * console.log(root); // 64-character hex string
 */
function buildMerkleRoot(hashes) {
  // ── Input validation ──────────────────────────────────────────────────────
  if (!Array.isArray(hashes)) {
    throw new TypeError(`buildMerkleRoot: expected an Array, got ${typeof hashes}`);
  }

  if (hashes.length === 0) {
    throw new RangeError('buildMerkleRoot: hashes array must not be empty');
  }

  const invalidIndex = hashes.findIndex((h) => !isValidSHA256Hex(h));
  if (invalidIndex !== -1) {
    throw new TypeError(
      `buildMerkleRoot: invalid SHA-256 hex string at index ${invalidIndex}: "${hashes[invalidIndex]}"`
    );
  }

  // ── Edge case: single leaf ─────────────────────────────────────────────────
  if (hashes.length === 1) {
    return hashes[0];
  }

  // ── Build the tree bottom-up ───────────────────────────────────────────────
  let currentLevel = hashes.map((h) => h.toLowerCase());

  while (currentLevel.length > 1) {
    currentLevel = buildNextLevel(currentLevel);
  }

  return currentLevel[0];
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = { buildMerkleRoot };