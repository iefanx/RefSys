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
  <div class="flex min-h-screen items-center justify-center px-2">
    <div class="w-full max-w-md bg-gray-900 rounded-lg shadow-md p-2">
      <h1 class="text-xl font-bold text-center text-gray-100">${title}</h1>
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
        <form action="/api/encrypt" method="get" class="space-y-2">
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

  // Generate a unique hash from the event data (ID)
  const eventHash = crypto.createHmac('sha256', masterSecret)
    .update(id.toString())
    .digest('hex');
  
  // Use the hash as salt for key generation
  const encryptionKey = generateKey(masterSecret, eventHash, currentKeyVersion);
  const { encryptedData, iv } = encrypt(cn.toString(), encryptionKey);

  const encryptContent = `
    <div class="space-y-4">
      <div class="bg-gray-900 rounded-lg p-2">
        <h3 class="text-lg font-semibold text-gray-200 mb-2">Security Information</h3>
        <p class="text-sm text-gray-300 leading-relaxed">
          Your data has been encrypted using a secure process:
          <ul class="list-disc list-inside mt-2 space-y-1">
            <li>A unique hash is generated from your event data</li>
            <li>This hash is used to derive the encryption key</li>
            <li>No sensitive data is stored - everything can be regenerated using your event data</li>
          </ul>
        </p>
      </div>

      <div class="space-y-2">
        <div>
          <label class="block text-sm font-bold text-gray-300">Event Hash:</label>
          <input class="w-full bg-gray-800 rounded p-2 mt-1 text-sm font-mono text-gray-200" 
            readonly value="${eventHash}" />
        </div>

        <div>
          <label class="block text-sm font-bold text-gray-300">Initialization Vector (IV):</label>
          <input class="w-full bg-gray-800 rounded p-2 mt-1 text-sm font-mono text-gray-200" 
            readonly value="${iv}" />
        </div>

        <div>
          <label class="block text-sm font-bold text-gray-300">Encrypted Data:</label>
          <textarea class="w-full bg-gray-800 rounded p-2 mt-1 text-sm font-mono text-gray-200" 
            readonly>${encryptedData}</textarea>
        </div>
      </div>

      <div class="flex justify-center">
        <a href="/api/encrypt?action=decrypt&encryptedCN=${encodeURIComponent(encryptedData)}&iv=${iv}&id=${id}&version=${currentKeyVersion}" 
          class="bg-green-600 hover:bg-green-700 rounded-lg px-6 py-3 text-center text-white font-bold inline-flex items-center space-x-2">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd" />
          </svg>
          <span>Generate Hash & Decrypt</span>
        </a>
      </div>
    </div>`;

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
