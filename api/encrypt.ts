import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'crypto';

// Securely stored master secret and key version
const masterSecret = 'myMasterSecretKeyForHMAC';
let currentKeyVersion = 1;

// Generate a key using PBKDF2
function generateKey(secret: string, salt: string, version: number): Buffer {
  return crypto.pbkdf2Sync(`${secret}-${version}`, salt, 100000, 32, 'sha256');
}

// Encrypt data using AES
function encrypt(data: string, key: Buffer): { encryptedData: string; iv: string } {
  const iv = crypto.randomBytes(16); // Random initialization vector
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encryptedData: encrypted, iv: iv.toString('hex') };
}

// Decrypt data using AES
function decrypt(encryptedData: string, key: Buffer, iv: string): string {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Generate dynamic HTML
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
<body class="bg-black text-white font-sans">
  <div class="flex min-h-screen items-center justify-center px-4">
    <div class="w-full max-w-md bg-gray-900 rounded-lg shadow-md p-6">
      <h1 class="text-2xl font-bold text-center text-gray-100">${title}</h1>
      <p class="text-xs text-gray-400 mt-2 text-center">A secure encryption demo built with modern cryptographic methods.</p>
      <div class="mt-4">${content}</div>
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
        <form action="/api/encrypt" method="get" class="space-y-4">
          <input type="hidden" name="action" value="encrypt">
          <label class="block">
            <span class="text-sm text-gray-300">Unique Event Data (ID):</span>
            <input type="text" name="id" placeholder="Enter unique ID..." 
              class="w-full bg-gray-800 rounded p-2 mt-1 text-sm text-gray-200" required>
          </label>
          <label class="block">
            <span class="text-sm text-gray-300">Data to Encrypt (CN):</span>
            <textarea name="cn" placeholder="Enter data to encrypt..." 
              class="w-full bg-gray-800 rounded p-2 mt-1 text-sm text-gray-200" required></textarea>
          </label>
          <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 rounded p-2 text-sm font-bold text-white">
            Encrypt Data
          </button>
        </form>`;
      return res.send(generateHTML('Secure Encryption Demo', homeContent));
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

      const encryptContent = 
        <p class="text-sm text-gray-300"<p class="text-sm text-gray-300">The data has been securely encrypted using an irreversible hash generated from your unique ID.</p>
        <div class="mt-4">
          <label class="block text-sm font-bold text-gray-300">Encrypted Data:</label>
          <textarea class="w-full bg-gray-800 rounded p-2 mt-1 text-sm text-gray-200" readonly>${encryptedData}</textarea>
        </div>
        <a href="/api/encrypt?action=decrypt&encryptedCN=${encodeURIComponent(
          encryptedData
        )}&iv=${iv}&id=${id}&version=${currentKeyVersion}" 
          class="block mt-4 bg-green-600 hover:bg-green-700 rounded p-2 text-center text-white font-bold">
          Decrypt Data
        </a>;
      return res.send(generateHTML('Encryption Result', encryptContent));
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
        <p class="text-sm text-gray-300">The encrypted data was decrypted using the same hash derived from your unique ID.</p>
        <div class="mt-4">
          <label class="block text-sm font-bold text-gray-300">Decrypted Data:</label>
          <textarea class="w-full bg-gray-800 rounded p-2 mt-1 text-sm text-gray-200" readonly>${decryptedData}</textarea>
        </div>
        <a href="/api/encrypt" 
          class="block mt-4 bg-gray-600 hover:bg-gray-700 rounded p-2 text-center text-white font-bold">
          Back to Home
        </a>`;
      return res.send(generateHTML('Decryption Result', decryptContent));
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
