const path = require("path");
const { generateFileHash } = require("./src/core/hasher");

(async () => {
  try {
    const filePath = path.join(__dirname, "test.txt");
    const hash = await generateFileHash(filePath);
    console.log("SHA-256:", hash);
  } catch (err) {
    console.error(err);
  }
})();