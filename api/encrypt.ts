import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'crypto';

// Simulate master secret and current key version
const masterSecret = 'myMasterSecretKeyForHMAC'; // Securely stored
let currentKeyVersion = 2; // Increment this on key rotation

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
<body class="bg-gray-900 text-gray-100 font-sans">
  <div class="min-h-screen flex items-center justify-center p-6">
    <div class="w-full max-w-2xl bg-gray-800 rounded-lg shadow-lg p-8">
      <h1 class="text-3xl font-bold text-center mb-6">${title}</h1>
      ${content}
    </div>
  </div>
</body>
</html>`;
}

// Main handler function
export default function handler(req: VercelRequest, res: VercelResponse) {
  try {
    const { cn = '', id = '', version = currentKeyVersion, action = 'encrypt' } = req.query;

    if (!cn || !id) {
      const errorHTML = generateHTML(
        'Error',
        `<p class="text-center text-red-500">Missing required parameters: <code>cn</code> and <code>id</code>.</p>`
      );
      return res.status(400).send(errorHTML);
    }

    const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex'); // Derive salt from ID
    const decryptionVersion = parseInt(version as string, 10);

    if (action === 'encrypt') {
      // Encrypt data with the current key version
      const encryptionKey = generateKey(masterSecret, salt, currentKeyVersion);
      const { encryptedData, iv } = encrypt(cn.toString(), encryptionKey);

      const content = `
        <p class="mb-4">
          The data has been successfully <span class="text-green-500 font-bold">encrypted</span> using an 
          irreversible hash derived from the provided ID (<code>${id}</code>) and the current key version 
          (<code>${currentKeyVersion}</code>).
        </p>
        <div class="mb-6">
          <h2 class="font-bold text-lg mb-2">Encrypted Data:</h2>
          <textarea class="w-full bg-gray-700 rounded-lg p-2" readonly>${encryptedData}</textarea>
        </div>
        <div class="mb-6">
          <h2 class="font-bold text-lg mb-2">IV:</h2>
          <textarea class="w-full bg-gray-700 rounded-lg p-2" readonly>${iv}</textarea>
        </div>
        <div class="mb-6">
          <h2 class="font-bold text-lg mb-2">Irreversible Hash:</h2>
          <textarea class="w-full bg-gray-700 rounded-lg p-2" readonly>${salt}</textarea>
        </div>
        <a href="?action=decrypt&encryptedCN=${encodeURIComponent(
          encryptedData
        )}&iv=${iv}&id=${id}&version=${currentKeyVersion}" 
          class="block text-center bg-green-500 hover:bg-green-600 rounded-lg px-4 py-2 font-bold text-gray-900">
          Decrypt Data
        </a>
      `;

      return res.status(200).send(generateHTML('Encryption Successful', content));
    } else if (action === 'decrypt') {
      // Decrypt data with the specified version
      const { encryptedCN, iv } = req.query;

      if (!encryptedCN || !iv) {
        const errorHTML = generateHTML(
          'Error',
          `<p class="text-center text-red-500">Missing required parameters for decryption: <code>encryptedCN</code> and <code>iv</code>.</p>`
        );
        return res.status(400).send(errorHTML);
      }

      const decryptionKey = generateKey(masterSecret, salt, decryptionVersion);
      const decryptedData = decrypt(encryptedCN.toString(), decryptionKey, iv.toString());

      const content = `
        <p class="mb-4">
          The data has been successfully <span class="text-blue-500 font-bold">decrypted</span> using the 
          hash derived from the provided ID (<code>${id}</code>) and version (<code>${decryptionVersion}</code>).
        </p>
        <div class="mb-6">
          <h2 class="font-bold text-lg mb-2">Decrypted Data:</h2>
          <textarea class="w-full bg-gray-700 rounded-lg p-2" readonly>${decryptedData}</textarea>
        </div>
        <a href="/" 
          class="block text-center bg-gray-500 hover:bg-gray-600 rounded-lg px-4 py-2 font-bold text-gray-900">
          Back to Encrypt
        </a>
      `;

      return res.status(200).send(generateHTML('Decryption Successful', content));
    }

    const errorHTML = generateHTML(
      'Error',
      `<p class="text-center text-red-500">Invalid action specified. Use <code>encrypt</code> or <code>decrypt</code>.</p>`
    );
    return res.status(400).send(errorHTML);
  } catch (error) {
    const errorHTML = generateHTML(
      'Error',
      `<p class="text-center text-red-500">An error occurred: ${error.message}</p>`
    );
    res.status(500).send(errorHTML);
  }
}
