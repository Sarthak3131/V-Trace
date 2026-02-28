const fs = require("fs");
const crypto = require("crypto");

/**
 * Generates SHA-256 hash for each fixed-size chunk of a file
 * @param {string} filePath
 * @param {number} chunkSize - size in bytes (default 4MB)
 * @returns {Promise<string[]>}
 */
async function generateChunkHashes(filePath, chunkSize = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunkHashes = [];
    const stream = fs.createReadStream(filePath, {
      highWaterMark: chunkSize,
    });

    stream.on("data", (chunk) => {
      const hash = crypto.createHash("sha256").update(chunk).digest("hex");
      chunkHashes.push(hash);
    });

    stream.on("end", () => {
      resolve(chunkHashes);
    });

    stream.on("error", (err) => {
      reject(err);
    });
  });
}

module.exports = { generateChunkHashes };