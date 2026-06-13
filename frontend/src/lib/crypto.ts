function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(buffer: ArrayBuffer): string {
  const Uint8 = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < Uint8.length; i++) {
    hex += ('00' + Uint8[i].toString(16)).slice(-2);
  }
  return hex;
}

async function hashPair(leftHex: string, rightHex: string): Promise<string> {
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const concatenated = new Uint8Array(left.length + right.length);
  concatenated.set(left, 0);
  concatenated.set(right, left.length);

  const hashBuffer = await window.crypto.subtle.digest('SHA-256', concatenated);
  return bytesToHex(hashBuffer);
}

export async function buildMerkleRoot(hashes: string[]): Promise<string> {
  if (hashes.length === 0) {
    throw new RangeError('buildMerkleRoot: hashes array must not be empty');
  }

  if (hashes.length === 1) {
    return hashes[0];
  }

  let currentLevel = hashes.map((h) => h.toLowerCase());

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    const nodes = currentLevel.length % 2 === 0
      ? currentLevel
      : [...currentLevel, currentLevel[currentLevel.length - 1]];

    for (let i = 0; i < nodes.length; i += 2) {
      const parent = await hashPair(nodes[i], nodes[i + 1]);
      nextLevel.push(parent);
    }
    currentLevel = nextLevel;
  }

  return currentLevel[0];
}

export async function hashFileInChunks(
  file: File,
  chunkSize: number = 1024 * 1024, // 1MB default
  onProgress?: (progress: number) => void,
  onChunkHashed?: (chunkIndex: number, hash: string) => void
): Promise<{ originalHash: string; chunkHashes: string[]; merkleRoot: string }> {
  const totalChunks = Math.ceil(file.size / chunkSize);
  const chunkHashes: string[] = [];

  // 1. Calculate chunk hashes
  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const slice = file.slice(start, end);
    
    // Read slice as array buffer
    const arrayBuffer = await new Promise<ArrayBuffer>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(slice);
    });

    const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
    const chunkHash = bytesToHex(hashBuffer);
    chunkHashes.push(chunkHash);

    if (onChunkHashed) {
      onChunkHashed(i, chunkHash);
    }

    if (onProgress) {
      // Dedicate first 80% of progress to chunk hashing
      onProgress(Math.round(((i + 1) / totalChunks) * 80));
    }
  }

  // 2. Calculate original file hash (entire file)
  if (onProgress) onProgress(85);
  const fullFileBuffer = await new Promise<ArrayBuffer>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
  
  const originalHashBuffer = await window.crypto.subtle.digest('SHA-256', fullFileBuffer);
  const originalHash = bytesToHex(originalHashBuffer);
  
  if (onProgress) onProgress(95);

  // 3. Compute Merkle Root
  const merkleRoot = await buildMerkleRoot(chunkHashes);
  
  if (onProgress) onProgress(100);

  return {
    originalHash,
    chunkHashes,
    merkleRoot,
  };
}
