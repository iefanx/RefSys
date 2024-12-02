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

// Main handler function
export default function handler(req: VercelRequest, res: VercelResponse) {
  try {
    const { cn, id, encryptedData, iv, action = 'encrypt', version = currentKeyVersion } = req.query;

    let content = `
      <div class="text-center mt-6">
        <button 
          id="demoEncrypt" 
          class="bg-blue-600 text-white px-6 py-3 rounded-md font-semibold hover:bg-blue-700 transition"
          onclick="startEncryptDemo()"
        >
          Encrypt Data
        </button>
        <button 
          id="demoDecrypt" 
          class="bg-green-600 text-white px-6 py-3 rounded-md font-semibold hover:bg-green-700 transition ml-4"
          onclick="startDecryptDemo()"
        >
          Decrypt Data
        </button>
      </div>
    `;

    if (action === 'encrypt' && cn && id) {
      // Perform encryption
      const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex');
      const encryptionKey = generateKey(masterSecret, salt, currentKeyVersion);
      const { encryptedData, iv } = encrypt(cn.toString(), encryptionKey);

      content = `
        <h2 class="text-2xl font-bold text-center">Encryption Successful</h2>
        <div class="text-left mt-6 space-y-3">
          <p><strong>Original Data:</strong> ${cn}</p>
          <p><strong>Salt Derived:</strong> ${salt}</p>
          <p><strong>Initialization Vector (IV):</strong> ${iv}</p>
          <p><strong>Encrypted Data:</strong> ${encryptedData}</p>
          <p><strong>Key Version:</strong> ${currentKeyVersion}</p>
        </div>
        <div class="text-center mt-6">
          <button 
            id="demoDecrypt" 
            class="bg-green-600 text-white px-6 py-3 rounded-md font-semibold hover:bg-green-700 transition"
            onclick="startDecryptDemo('${encryptedData}', '${iv}', ${currentKeyVersion}, '${id}')"
          >
            Decrypt This Data
          </button>
        </div>
      `;
    } else if (action === 'decrypt' && encryptedData && iv) {
      // Perform decryption
      const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex');
      const decryptionKey = generateKey(masterSecret, salt, parseInt(version as string, 10));
      const decryptedData = decrypt(encryptedData.toString(), decryptionKey, iv.toString());

      content = `
        <h2 class="text-2xl font-bold text-center">Decryption Successful</h2>
        <div class="text-left mt-6 space-y-3">
          <p><strong>Encrypted Data:</strong> ${encryptedData}</p>
          <p><strong>Initialization Vector (IV):</strong> ${iv}</p>
          <p><strong>Decrypted Data:</strong> ${decryptedData}</p>
          <p><strong>Key Version Used:</strong> ${version}</p>
        </div>
      `;
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Encryption Demo</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
          body { background-color: #000; color: #fff; font-family: 'Inter', sans-serif; }
        </style>
      </head>
      <body class="flex items-center justify-center min-h-screen">
        <div class="max-w-2xl w-full bg-gray-900 p-6 rounded-lg shadow-lg">
          <h1 class="text-3xl font-bold text-center mb-6">Encryption & Decryption Demo</h1>
          ${content}
        </div>
        <script>
          function startEncryptDemo() {
            const exampleCN = 'SensitiveData';
            const exampleID = '12345';
            window.location.href = '?cn=' + encodeURIComponent(exampleCN) + '&id=' + encodeURIComponent(exampleID) + '&action=encrypt';
          }

          function startDecryptDemo(encryptedData, iv, version, id) {
            window.location.href = '?encryptedData=' + encodeURIComponent(encryptedData) + '&iv=' + encodeURIComponent(iv) + '&action=decrypt&id=' + encodeURIComponent(id) + '&version=' + version;
          }
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Error</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
          body { background-color: #000; color: #fff; font-family: 'Inter', sans-serif; }
        </style>
      </head>
      <body class="flex items-center justify-center min-h-screen">
        <div class="text-center">
          <h1 class="text-2xl font-bold">Error</h1>
          <p>An error occurred: ${error.message}</p>
        </div>
      </body>
      </html>
    `);
  }
}
