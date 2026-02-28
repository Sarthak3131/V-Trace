const path = require("path");
const { generateChunkHashes } = require("./src/core/chunkHasher");

(async () => {
  try {
    const filePath = path.join(__dirname, "test.txt");
    const hashes = await generateChunkHashes(filePath);
    console.log("Chunk Hashes:", hashes);
  } catch (err) {
    console.error(err);
  }
})();