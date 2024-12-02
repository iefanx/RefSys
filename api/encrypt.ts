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
    const { cn = '', id = '', action = 'encrypt', version = currentKeyVersion } = req.query;

    let demonstrationContent = `
      <div class="text-center mt-6">
        <button 
          id="demoButton" 
          class="bg-blue-600 text-white px-6 py-2 rounded-md font-semibold hover:bg-blue-700 transition"
          onclick="startDemo()"
        >
          Start Demonstration
        </button>
      </div>
    `;

    let explanation = `
      <p class="text-lg">This application demonstrates the encryption and decryption process using AES-256-CBC. Below are the steps:</p>
      <ul class="list-disc pl-5 space-y-2 mt-4 text-left">
        <li><strong>Encryption:</strong> The provided data is encrypted with a versioned key and a randomly generated Initialization Vector (IV).</li>
        <li><strong>Decryption:</strong> The encrypted data can be decrypted with the correct version of the key and the same IV.</li>
        <li><strong>Versioned Keys:</strong> The system uses versioned keys for added security, allowing for key rotation.</li>
        <li><strong>PBKDF2:</strong> The key is derived using PBKDF2 for additional strength against brute-force attacks.</li>
      </ul>
    `;

    let content = demonstrationContent + explanation;

    if (cn && id) {
      const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex');
      const keyVersion = parseInt(version as string, 10);

      if (action === 'encrypt') {
        const encryptionKey = generateKey(masterSecret, salt, currentKeyVersion);
        const { encryptedData, iv } = encrypt(cn.toString(), encryptionKey);

        content = `
          <h2 class="text-xl font-bold">Encryption Results</h2>
          <div class="text-left space-y-2 mt-4">
            <p><strong>Original Data:</strong> ${cn}</p>
            <p><strong>Salt Derived:</strong> ${salt}</p>
            <p><strong>Initialization Vector (IV):</strong> ${iv}</p>
            <p><strong>Encrypted Data:</strong> ${encryptedData}</p>
            <p><strong>Key Version:</strong> ${currentKeyVersion}</p>
          </div>
          ${demonstrationContent}
        `;
      } else if (action === 'decrypt') {
        const decryptionKey = generateKey(masterSecret, salt, keyVersion);
        const { encryptedCN, iv } = req.query;

        if (!encryptedCN || !iv) {
          content = `
            <p class="text-lg text-red-500">Missing required parameters for decryption: <code>encryptedCN</code> and <code>iv</code>.</p>
          `;
        } else {
          const decryptedData = decrypt(encryptedCN.toString(), decryptionKey, iv.toString());

          content = `
            <h2 class="text-xl font-bold">Decryption Results</h2>
            <div class="text-left space-y-2 mt-4">
              <p><strong>Encrypted Data:</strong> ${encryptedCN}</p>
              <p><strong>Initialization Vector (IV):</strong> ${iv}</p>
              <p><strong>Decrypted Data:</strong> ${decryptedData}</p>
              <p><strong>Key Version Used:</strong> ${keyVersion}</p>
            </div>
            ${demonstrationContent}
          `;
        }
      }
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Encryption Demonstration</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-black text-white min-h-screen flex items-center justify-center p-4">
        <div class="max-w-2xl w-full bg-gray-900 p-6 rounded-lg shadow-lg">
          <h1 class="text-3xl font-bold text-center mb-6">Encryption & Decryption Demo</h1>
          ${content}
        </div>
        <script>
          function startDemo() {
            const exampleCN = 'ExampleData';
            const exampleID = '12345';
            window.location.href = '?cn=' + encodeURIComponent(exampleCN) + '&id=' + encodeURIComponent(exampleID) + '&action=encrypt';
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
      </head>
      <body class="bg-black text-white min-h-screen flex items-center justify-center">
        <div class="text-center">
          <h1 class="text-2xl font-bold">Error</h1>
          <p class="text-lg">An error occurred: ${error.message}</p>
        </div>
      </body>
      </html>
    `);
  }
}
