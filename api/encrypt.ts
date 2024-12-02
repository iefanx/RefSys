import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'crypto';

// Simulated master secret and current key version
const masterSecret = 'myMasterSecretKeyForHMAC'; // Securely stored
let currentKeyVersion = 1; // Increment this when the key is rotated

// Function to generate a key using PBKDF2 and versioning
function generateKey(secret: string, salt: string, version: number): Buffer {
  return crypto.pbkdf2Sync(`${secret}-${version}`, salt, 100000, 32, 'sha256'); // Generate a 256-bit key
}

// Function to encrypt data using AES with versioning
function encrypt(data: string, key: Buffer): { encryptedData: string; iv: string } {
  const iv = crypto.randomBytes(16); // Random initialization vector (IV)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encryptedData: encrypted, iv: iv.toString('hex') };
}

// Function to decrypt data using AES
function decrypt(encryptedData: string, key: Buffer, iv: string): string {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// HTML Template
function generateHTML(title: string, content: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-black text-gray-100 font-sans">
  <div class="min-h-screen flex flex-col items-center justify-center p-6">
    <div class="w-full max-w-lg bg-gray-900 rounded-lg shadow-lg p-8">
      <h1 class="text-2xl font-bold text-center mb-4">${title}</h1>
      <p class="text-sm text-gray-400 text-center mb-6">
        This encryption method uses HMAC with unique event data to generate an irreversible hash. 
        The hash is then used to encrypt the data without saving it. During decryption, the same 
        irreversible hash is generated again to retrieve the original data.
      </p>
      ${content}
    </div>
  </div>
</body>
</html>`;
}

// Main handler function
export default function handler(req: VercelRequest, res: VercelResponse) {
  try {
    const { action = 'home', cn = '', id = '', version = currentKeyVersion } = req.query;

    if (action === 'home') {
      const homeContent = `
        <form action="/" method="get" class="space-y-4">
          <input type="hidden" name="action" value="encrypt">
          <label class="block">
            <span class="text-sm">Unique Event Data (ID):</span>
            <input type="text" name="id" placeholder="Enter unique ID..." 
              class="w-full bg-gray-800 rounded-lg p-2 mt-1 text-sm text-gray-300" required>
          </label>
          <label class="block">
            <span class="text-sm">Data to Encrypt (CN):</span>
            <textarea name="cn" placeholder="Enter data to encrypt..." 
              class="w-full bg-gray-800 rounded-lg p-2 mt-1 text-sm text-gray-300" required></textarea>
          </label>
          <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 rounded-lg px-4 py-2 text-sm font-bold">
            Encrypt Data
          </button>
        </form>
      `;
      return res.send(generateHTML('Encryption Demo', homeContent));
    }

    if (action === 'encrypt') {
      if (!cn || !id) {
        const errorHTML = generateHTML(
          'Error',
          `<p class="text-red-500 text-center">Both Event Data (ID) and Data to Encrypt (CN) are required!</p>`
        );
        return res.status(400).send(errorHTML);
      }

      const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex');
      const encryptionKey = generateKey(masterSecret, salt, currentKeyVersion);
      const { encryptedData, iv } = encrypt(cn.toString(), encryptionKey);

      const encryptContent = `
        <p class="mb-4 text-sm text-gray-400">
          The data has been encrypted using an irreversible hash generated from the event data 
          (<code>${id}</code>) and the current key version (<code>${currentKeyVersion}</code>).
        </p>
        <div class="mb-4">
          <h2 class="font-bold text-sm">Encrypted Data:</h2>
          <textarea class="w-full bg-gray-800 rounded-lg p-2 text-sm text-gray-300" readonly>${encryptedData}</textarea>
        </div>
        <div class="mb-4">
          <h2 class="font-bold text-sm">IV:</h2>
          <textarea class="w-full bg-gray-800 rounded-lg p-2 text-sm text-gray-300" readonly>${iv}</textarea>
        </div>
        <div class="mb-4">
          <h2 class="font-bold text-sm">Irreversible Hash:</h2>
          <textarea class="w-full bg-gray-800 rounded-lg p-2 text-sm text-gray-300" readonly>${salt}</textarea>
        </div>
        <a href="/api/encrypt?action=decrypt&encryptedCN=${encodeURIComponent(
          encryptedData
        )}&iv=${iv}&id=${id}&version=${currentKeyVersion}" 
          class="w-full block bg-green-600 hover:bg-green-700 rounded-lg px-4 py-2 text-center font-bold">
          Decrypt Data
        </a>
      `;
      return res.send(generateHTML('Encryption Successful', encryptContent));
    }

    if (action === 'decrypt') {
      const { encryptedCN, iv } = req.query;

      if (!encryptedCN || !iv || !id) {
        const errorHTML = generateHTML(
          'Error',
          `<p class="text-red-500 text-center">Missing required parameters for decryption!</p>`
        );
        return res.status(400).send(errorHTML);
      }

      const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex');
      const decryptionKey = generateKey(masterSecret, salt, parseInt(version as string, 10));
      const decryptedData = decrypt(encryptedCN.toString(), decryptionKey, iv.toString());

      const decryptContent = `
        <p class="mb-4 text-sm text-gray-400">
          The data has been decrypted using the hash derived from the event data (<code>${id}</code>).
        </p>
        <div class="mb-4">
          <h2 class="font-bold text-sm">Decrypted Data:</h2>
          <textarea class="w-full bg-gray-800 rounded-lg p-2 text-sm text-gray-300" readonly>${decryptedData}</textarea>
        </div>
        <a href="/" 
          class="w-full block bg-gray-600 hover:bg-gray-700 rounded-lg px-4 py-2 text-center font-bold">
          Back to Encryption Demo
        </a>
      `;
      return res.send(generateHTML('Decryption Successful', decryptContent));
    }

    const errorHTML = generateHTML(
      'Error',
      `<p class="text-red-500 text-center">Invalid action. Use <code>encrypt</code> or <code>decrypt</code>.</p>`
    );
    return res.status(400).send(errorHTML);
  } catch (error) {
    const errorHTML = generateHTML(
      'Error',
      `<p class="text-red-500 text-center">An unexpected error occurred: ${error.message}</p>`
    );
    res.status(500).send(errorHTML);
  }
}
