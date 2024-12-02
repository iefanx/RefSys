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
    const { cn = '', id = '', version = currentKeyVersion } = req.query;

    if (!cn || !id) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <title>Error</title>
            <script src="https://cdn.tailwindcss.com"></script>
          </head>
          <body class="bg-black text-white flex items-center justify-center min-h-screen">
            <div class="text-center">
              <h1 class="text-2xl font-bold">Error</h1>
              <p class="text-lg">Missing required parameters: <code>cn</code> and <code>id</code>.</p>
            </div>
          </body>
        </html>
      `);
    }

    const action = req.query.action || 'encrypt'; // Default to encryption
    const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex'); // Derive salt from ID

    let content;
    if (action === 'encrypt') {
      const encryptionKey = generateKey(masterSecret, salt, currentKeyVersion);
      const { encryptedData, iv } = encrypt(cn.toString(), encryptionKey);

      content = `
        <div class="space-y-4">
          <h2 class="text-xl font-bold">Encryption</h2>
          <p><strong>Original Data:</strong> ${cn}</p>
          <p><strong>Salt:</strong> ${salt}</p>
          <p><strong>IV:</strong> ${iv}</p>
          <p><strong>Encrypted Data:</strong> ${encryptedData}</p>
          <p><strong>Key Version:</strong> ${currentKeyVersion}</p>
        </div>
      `;
    } else if (action === 'decrypt') {
      const decryptionVersion = parseInt(version as string, 10);
      const decryptionKey = generateKey(masterSecret, salt, decryptionVersion);
      const { encryptedCN, iv } = req.query;

      if (!encryptedCN || !iv) {
        return res.send(`
          <!DOCTYPE html>
          <html lang="en">
            <head>
              <title>Error</title>
              <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-black text-white flex items-center justify-center min-h-screen">
              <div class="text-center">
                <h1 class="text-2xl font-bold">Error</h1>
                <p class="text-lg">Missing parameters for decryption: <code>encryptedCN</code> and <code>iv</code>.</p>
              </div>
            </body>
          </html>
        `);
      }

      const decryptedData = decrypt(encryptedCN.toString(), decryptionKey, iv.toString());

      content = `
        <div class="space-y-4">
          <h2 class="text-xl font-bold">Decryption</h2>
          <p><strong>Encrypted Data:</strong> ${encryptedCN}</p>
          <p><strong>Salt:</strong> ${salt}</p>
          <p><strong>IV:</strong> ${iv}</p>
          <p><strong>Decrypted Data:</strong> ${decryptedData}</p>
          <p><strong>Key Version:</strong> ${decryptionVersion}</p>
        </div>
      `;
    } else {
      content = '<p class="text-lg">Invalid action specified. Use "encrypt" or "decrypt".</p>';
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <title>Encryption/Decryption</title>
          <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-black text-white flex items-center justify-center min-h-screen">
          <div class="max-w-3xl mx-auto p-6 space-y-8 bg-gray-900 rounded-lg shadow-md">
            <h1 class="text-3xl font-bold text-center">Encryption/Decryption Handler</h1>
            ${content}
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <title>Error</title>
          <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-black text-white flex items-center justify-center min-h-screen">
          <div class="text-center">
            <h1 class="text-2xl font-bold">Error</h1>
            <p class="text-lg">An error occurred: ${error.message}</p>
          </div>
        </body>
      </html>
    `);
  }
}
