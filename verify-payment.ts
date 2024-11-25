import type { VercelRequest, VercelResponse } from '@vercel/node';
import axios from 'axios';
import crypto from 'node:crypto';

export default async function verifyHandler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight requests (OPTIONS method)
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  const hmacSecretKey = 'your-secret-hmac-key';

  const { verifyURL = '', encryptedCt = '', hmac } = req.query;

  function generateHmac(data: string) {
    return crypto.createHmac('sha256', hmacSecretKey)
      .update(data)
      .digest('base64url');
  }

  const dataToSign = `${verifyURL}|${encryptedCt}`;
  const computedHmac = generateHmac(dataToSign);

  if (computedHmac !== hmac) {
    return res.status(400).json({
      error: 'Invalid URL or tampered data'
    });
  }

  // Ensure verifyURL and encryptedCt are strings
  let url: string;
  let ciphertext: string;

  if (Array.isArray(verifyURL)) {
    url = verifyURL[0];
  } else {
    url = verifyURL;
  }

  if (Array.isArray(encryptedCt)) {
    ciphertext = encryptedCt[0];
  } else {
    ciphertext = encryptedCt;
  }

  const encryptionKey = Buffer.from('MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=', 'base64');

  function decrypt(ivCiphertextB64: string) {
    const ivCiphertext = Buffer.from(ivCiphertextB64, 'base64url');
    const iv = ivCiphertext.subarray(0, 16);
    const ciphertext = ivCiphertext.subarray(16);
    const cipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    let decrypted = Buffer.concat([cipher.update(ciphertext), cipher.final()]);
    return decrypted.toString('utf-8');
  }

  try {
    // Verify if the invoice is settled
    const verifyResponse = await axios.get(url);

    if (verifyResponse.status === 200 && verifyResponse.data.settled === true) {
      // Decrypt the ciphertext since the invoice is settled
      let decryptedData;
      try {
        decryptedData = decrypt(ciphertext);
        return res.status(200).json({ decryptedData });
      } catch (error) {
        return res.status(400).json({ error: 'Decryption failed' });
      }
    } else {
      return res.status(400).json({ error: 'Content is currently encrypted. Please complete your payment to decrypt and access the content.', hmac  });
    }
  } catch (error) {
    return res.status(500).json({ error: 'Verification failed', details: error.message });
  }
}