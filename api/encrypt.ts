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
  <title class="pt-3">${title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-black text-white font-sans">
  <div class="flex min-h-screen items-center justify-center ">
    <div class="w-full max-w-full md:max-w-md lg:max-w-md p-3 ">
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
    <div class="space-y-3">
      <div class="bg-gray-900 rounded-lg p-2">
        <h2 class="text-xl font-bold text-gray-100 mb-3">How It Works</h2>
        <div class="text-sm  space-y-2">
          <p class="leading-relaxed">
            This demo showcases a secure, database-free encryption system:
          </p>
          <ol class="list-decimal list-inside space-y-2">
            <li>Enter your unique event data (e.g., Event ID, tags)</li>
            <li>The system generates an irreversible cryptographic hash from this data</li>
            <li>This hash is used as a key to encrypt your content</li>
            <li>No sensitive data or keys are stored - everything can be regenerated using your event data</li>
            <li>To decrypt, you'll need to provide the same event data to regenerate the hash</li>
          </ol>
        </div>
      </div>

      <form action="/api/encrypt" method="get" class="space-y-6">
        <input type="hidden" name="action" value="encrypt">
        
        <div class="space-y-1 px-2">
          <label class="block">
            <span class="text-sm font-semibold text-gray-300">Unique Event Data (ID):</span>
            <div class="mt-1">
              <input 
                type="text" 
                name="id" 
                placeholder="e.g., Event ID, Tags" 
                class="w-full bg-gray-800 rounded-lg p-3 text-sm text-gray-200 border border-gray-700 focus:border-blue-500 focus:ring-1 focus:ring-blue-500" 
                required
              >
            </div>
            <p class="mt-1 text-xs text-gray-400">This data will be used to generate the encryption hash. Must be provided again for decryption.</p>
          </label>
        </div>

        <div class="space-y-1 px-2">
          <label class="block">
            <span class="text-sm font-semibold text-gray-300">Content to Encrypt:</span>
            <div class="mt-1">
              <textarea 
                name="cn" 
                placeholder="Enter the sensitive data you want to encrypt..." 
                class="w-full bg-gray-800 rounded-lg p-3 text-sm text-gray-200 border border-gray-700 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 min-h-[100px]" 
                required
              ></textarea>
            </div>
            <p class="mt-1 text-xs text-gray-400">This content will be encrypted using a hash derived from your event data.</p>
          </label>
        </div>
        <div class= "px-2">
        <button 
          type="submit" 
          class="w-full bg-blue-600 hover:bg-blue-700 rounded-lg py-3 px-4 text-sm font-bold text-white transition-colors duration-200 inline-flex items-center justify-center space-x-2"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
          </svg>
          <span>Generate Hash & Encrypt Data</span>
        </button>
        </div>
      </form>

      <div class="px-2">
      <div class="bg-blue-900/20 rounded-lg p-4 border border-blue-800/30">
        <div class="flex items-start space-x-3">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-blue-400 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div class="flex-1">
            <h3 class="text-sm font-semibold text-blue-400">Security Note</h3>
            <p class="mt-1 text-xs text-gray-300">
              This system uses cryptographic hashing to eliminate the need for storing sensitive keys or data. 
              The hash generated from your event data is irreversible but reproducible, 
              allowing for secure encryption and decryption without a centralized database.
            </p>
          </div>
        </div>
      </div>
    </div>
    </div>`;

  return res.send(generateHTML('Secure Database-Free Encryption Demo', homeContent));
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
      <div class="bg-gray-900 rounded-lg p-3 py-2">
        <h3 class="text-lg font-semibold text-gray-200 mb-2">Security Information</h3>
        <p class="text-sm text-gray-300 leading-relaxed">
          Your data has been encrypted using a secure process:
          <ul class="list-disc text-sm list-inside mt-2 space-y-1">
            <li>A unique hash is generated from your event data</li>
            <li>This hash is used to derive the encryption key</li>
            <li>No sensitive data is stored - everything can be regenerated using your event data</li>
          </ul>
        </p>
      </div>

      <div class="space-y-2 px-2">
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
          class="bg-green-600 hover:bg-green-700 rounded-lg px-4 text-sm py-2 text-center text-white font-bold inline-flex items-center space-x-2">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd" />
          </svg>
          <span class="text-sm">Generate Hash & Decrypt</span>
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

  // Regenerate the same hash from event data
  const eventHash = crypto.createHmac('sha256', masterSecret)
    .update(id.toString())
    .digest('hex');
  
  // Generate decryption key using the regenerated hash
  const decryptionKey = generateKey(masterSecret, eventHash, parseInt(version as string, 10));
  
  // Decrypt the data using the regenerated key and original IV
  const decryptedData = decrypt(encryptedCN.toString(), decryptionKey, iv.toString());

  const decryptContent = `
    <div class="space-y-6">
      <div class="bg-gray-900 rounded-lg p-3 py-2">
        <h3 class="text-lg font-semibold text-gray-200 mb-2">Decryption Process</h3>
        <p class="text-sm text-gray-300 leading-relaxed">
          Your data has been successfully decrypted using a secure, database-free process:
          <ul class="list-disc text-sm list-inside mt-2 space-y-1">
            <li>The original hash was regenerated using your event data</li>
            <li>This reconstructed hash was used to derive the decryption key</li>
            <li>The decryption process used the original IV for security</li>
            <li>No keys or hashes needed to be stored in a database</li>
          </ul>
        </p>
      </div>

      <div class="space-y-4 px-2">
        <div>
          <label class="block text-sm font-bold text-gray-300">Regenerated Hash:</label>
          <input class="w-full bg-gray-800 rounded p-2 mt-1 text-sm font-mono text-gray-200" 
            readonly value="${eventHash}" />
        </div>

        <div>
          <label class="block text-sm font-bold text-gray-300">Used IV:</label>
          <input class="w-full bg-gray-800 rounded p-2 mt-1 text-sm font-mono text-gray-200" 
            readonly value="${iv}" />
        </div>

        <div>
          <label class="block text-sm font-bold text-gray-300">Decrypted Data:</label>
          <textarea class="w-full bg-gray-800 rounded p-2 mt-1 text-sm text-gray-200" 
            readonly>${decryptedData}</textarea>
        </div>
      </div>

      <div class="flex justify-center space-x-4">
        
        <a href="/api/encrypt" 
          class="bg-green-600 hover:bg-green-700 rounded-lg px-4 py-2 text-center text-white text-smfont-bold inline-flex items-center space-x-2">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd" />
          </svg>
          <span>Encrypt New Data</span>
        </a>
      </div>
    </div>`;

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
