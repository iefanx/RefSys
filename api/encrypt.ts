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
      return res.status(400).json({ error: 'Missing required parameters: cn and id.' });
    }

    const action = req.query.action || 'encrypt'; // Default to encryption
    const salt = crypto.createHmac('sha256', masterSecret).update(id.toString()).digest('hex'); // Derive salt from ID

    if (action === 'encrypt') {
      // Encrypt data with the current key version
      const encryptionKey = generateKey(masterSecret, salt, currentKeyVersion);
      const { encryptedData, iv } = encrypt(cn.toString(), encryptionKey);

      return res.status(200).json({
        encryptedCN: encryptedData,
        iv,
        version: currentKeyVersion,
      });
    } else if (action === 'decrypt') {
      // Decrypt data with the specified version
      const decryptionVersion = parseInt(version as string, 10);
      const decryptionKey = generateKey(masterSecret, salt, decryptionVersion);
      const { encryptedCN, iv } = req.query;

      if (!encryptedCN || !iv) {
        return res.status(400).json({ error: 'Missing required parameters for decryption: encryptedCN and iv.' });
      }

      const decryptedData = decrypt(encryptedCN.toString(), decryptionKey, iv.toString());

      return res.status(200).json({
        decryptedCN: decryptedData,
        version: decryptionVersion,
      });
    }

    return res.status(400).json({ error: 'Invalid action specified. Use "encrypt" or "decrypt".' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred.', details: error.message });
  }
}
