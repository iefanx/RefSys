import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'node:crypto';
import axios from 'axios';
import QRCode from 'qrcode';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { ct = '', ln = '', pr = '', hmac = '' } = req.query;
  const ctString = Array.isArray(ct) ? ct[0] : ct;
  const lnString = Array.isArray(ln) ? ln[0] : ln;
  const prString = Array.isArray(pr) ? pr[0] : pr;
  const hmacString = Array.isArray(hmac) ? hmac[0] : hmac;

  
  const hmacSecretKey = 'your-secret-hmac-key';


  function generateHmac(data: string) {
    return crypto.createHmac('sha256', hmacSecretKey)
      .update(data)
      .digest('base64url');
  }

  const dataToSign = `${lnString}|${prString}`;
  const computedHmac = generateHmac(dataToSign);

  if (computedHmac !== hmacString) {
    return res.status(400).send('<h1>Error</h1><p>Invalid URL or tampered data</p>');
  }


  try {
    const amountNumber = Number(prString);
    const invoiceResponse = await axios.get('https://api.getalby.com/lnurl/generate-invoice', {
      params: { ln: lnString, amount: amountNumber.toString() }
    });

    if (invoiceResponse.status === 200 && invoiceResponse.data.invoice) {
      const invoice = invoiceResponse.data.invoice;
      const qrCodeDataUrl = await QRCode.toDataURL(invoice.pr);
      const verifyUrl = invoice.verify;

      // Initial settlement check
      const initialVerifyResponse = await axios.get(verifyUrl);
      let isSettled = initialVerifyResponse.data.settled;

      // Prepare the response HTML
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Invoice QR Code</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; }
            img { margin-top: 20px; }
          </style>
          <script>
            let isSettled = ${isSettled};
            const cipherData = "${ctString}";
            const decryptedData = "test text";
            
            function updateStatus() {
              const dataElement = document.getElementById('data-display');
              const statusElement = document.getElementById('status');
              if (isSettled) {
                statusElement.textContent = 'Payment settled!';
                dataElement.textContent = 'Decrypted Data: ' + decryptedData;
              } else {
                statusElement.textContent = 'Waiting for payment...';
                dataElement.textContent = 'Encrypted Data: ' + cipherData;
              }
            }

            async function checkSettlement() {
              try {
                const response = await fetch('${verifyUrl}');
                const data = await response.json();
                isSettled = data.settled;
                updateStatus();
              } catch (error) {
                console.error('Error checking settlement:', error);
              }
            }

            // Initial update
            updateStatus();

            // Check settlement status every 5 seconds
            setInterval(checkSettlement, 5000);
          </script>
        </head>
        <body>
          <h1>Payment Invoice</h1>
          <p id="data-display"></p>
          <p>LN Address: ${lnString}</p>
          <p>Payment Request: ${prString}</p>
          <img src="${qrCodeDataUrl}" alt="QR Code for Invoice" />
          <p>Scan the QR code to make the payment.</p>
          <p id="status"></p>
        </body>
        </html>
      `;

      return res.send(html);
    } else {
      return res.status(500).send('<h1>Error</h1><p>Failed to generate invoice</p>');
    }
  } catch (error) {
    return res.status(500).send('<h1>Error</h1><p>API request failed</p>');
  }
}