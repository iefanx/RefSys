 import fetch from 'node-fetch';
import { VercelRequest, VercelResponse } from '@vercel/node';

const CONFIG = {
  ALBY_API_BASE_URL: 'https://api.getalby.com/lnurl',
  ERROR_MESSAGES: {
    MISSING_PARAMS: 'Missing required parameters: lightning addresses, price, or split percentage.',
    INVOICE_GENERATION_FAILED: 'Failed to generate invoice. Please try again.',
  },
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    const { address1, address2, price, split } = req.query;

    if (!address1 || !address2 || !price || !split) {
      return res.status(400).json({ error: CONFIG.ERROR_MESSAGES.MISSING_PARAMS });
    }

    const totalAmountMsats = parseInt(price as string, 10) * 1000; // Convert sats to millisats
    const splitPercentage = parseInt(split as string, 10);

    if (isNaN(totalAmountMsats) || isNaN(splitPercentage)) {
      return res.status(400).json({ error: 'Invalid price or split percentage.' });
    }

    // Calculate split amounts
    const address1Amount = Math.floor((totalAmountMsats * splitPercentage) / 100);
    const address2Amount = totalAmountMsats - address1Amount;

    // Generate invoices
    const [invoice1, invoice2] = await Promise.all([
      generateInvoice(address1 as string, address1Amount),
      generateInvoice(address2 as string, address2Amount),
    ]);

    if (!invoice1 || !invoice2) {
      return res.status(500).json({ error: CONFIG.ERROR_MESSAGES.INVOICE_GENERATION_FAILED });
    }

    // Send generated HTML response
    const htmlResponse = generateHtmlResponse(invoice1, invoice2);
    res.setHeader('Content-Type', 'text/html');
    res.status(200).send(htmlResponse);
  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
}

async function generateInvoice(lightningAddress: string, amount: number) {
  try {
    const url = `${CONFIG.ALBY_API_BASE_URL}/generate-invoice?ln=${encodeURIComponent(
      lightningAddress
    )}&amount=${encodeURIComponent(amount)}`;
    const response = await fetch(url);

    if (!response.ok) {
      console.error('Failed to generate invoice:', await response.text());
      return null;
    }

    const data = await response.json();
    return data.invoice || null;
  } catch (error) {
    console.error('Error in invoice generation:', error);
    return null;
  }
}


function generateHtmlResponse(invoice1, invoice2) {
  return `
    <!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Referral Payment System</title>
    <script src="https://cdn.jsdelivr.net/npm/qrious@4.0.2/dist/qrious.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
      body {
        background-color: #000000;
        font-family: 'Space Grotesk', sans-serif;
        color: #ffffff;
        margin: 0;
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 2rem;
      }

      .card {
        background: #0A0A0A;
        border: 1px solid #1a1a1a;
        border-radius: 24px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
        padding: 3rem;
        width: 100%;
        max-width: 1000px;
        text-align: center;
      }

      .card-header {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 2rem;
        background: linear-gradient(135deg, #FFD700, #FFA500);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }

      .description {
        font-size: 1.25rem;
        margin-bottom: 3rem;
        color: #9ca3af;
        line-height: 1.6;
      }

      .highlight {
        color: #FFD700;
        font-weight: 600;
      }

      .qr-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 2rem;
        margin-bottom: 3rem;
      }

      .qr-item {
        background: linear-gradient(145deg, #0f0f0f, #1a1a1a);
        padding: 2rem;
        border-radius: 20px;
        border: 1px solid #2a2a2a;
        display: flex;
        flex-direction: column;
        align-items: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      }

      .qr-item:hover {
        transform: translateY(-5px);
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        border-color: #FFD700;
      }

      .qr-title {
        font-size: 1.5rem;
        font-weight: 600;
        margin-bottom: 1.5rem;
        color: #ffffff;
      }

      canvas {
        margin-bottom: 1.5rem;
        padding: 1rem;
        background: white;
        border-radius: 12px;
        width: 250px;
        height: 250px;
      }

      .status {
        font-size: 1.1rem;
        padding: 0.75rem 1.5rem;
        border-radius: 12px;
        margin-top: 1rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        transition: all 0.3s ease;
      }

      .paid {
        background: linear-gradient(135deg, #4CAF50, #45a049);
        color: white;
        animation: pulse 2s infinite;
      }

      .not-paid {
        background: linear-gradient(135deg, #2a2a2a, #1a1a1a);
        color: #9ca3af;
        border: 1px solid #333;
      }

      .completion-message {
        display: none;
        flex-direction: column;
        align-items: center;
        gap: 1.5rem;
        padding: 2rem;
        background: linear-gradient(145deg, #1a1a1a, #0f0f0f);
        border-radius: 16px;
        border: 1px solid #FFD700;
        margin-top: 2rem;
      }

      .completion-message.visible {
        display: flex;
        animation: slideUp 0.5s ease-out;
      }

      .completion-message p {
        font-size: 1.5rem;
        font-weight: 600;
        color: #FFD700;
        margin: 0;
      }

      .restart-btn {
        background: linear-gradient(135deg, #FFD700, #FFA500);
        color: black;
        border: none;
        padding: 1rem 2rem;
        border-radius: 12px;
        font-weight: 700;
        font-size: 1.1rem;
        cursor: pointer;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 1px;
      }

      .restart-btn:hover {
        transform: scale(1.05);
        box-shadow: 0 5px 15px rgba(255, 215, 0, 0.3);
      }

      @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
      }

      @keyframes slideUp {
        from { 
          opacity: 0;
          transform: translateY(20px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }

      .split-control {
        margin-bottom: 2rem;
        padding: 1rem;
        background: linear-gradient(145deg, #0f0f0f, #1a1a1a);
        border-radius: 12px;
        border: 1px solid #2a2a2a;
      }

      .split-control label {
        display: block;
        margin-bottom: 0.5rem;
        color: #9ca3af;
      }

      .split-control input {
        background: #1a1a1a;
        border: 1px solid #333;
        padding: 0.5rem;
        border-radius: 8px;
        color: #ffffff;
        text-align: center;
        width: 80px;
        margin: 0 0.5rem;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1 class="card-header">
        Lightning Network Payment Split
      </h1>

      <div class="split-control">
        <label>Adjust Split Percentage</label>
        <input type="number" id="creatorSplit" min="0" max="100" value="70"> /
        <input type="number" id="referrerSplit" min="0" max="100" value="30">
      </div>

      <p class="description">
        Currently splitting <span id="splitPercentage" class="highlight">70% / 30%</span> of 
        <span id="totalAmount" class="highlight">500 sats</span> between the 
        <span class="highlight">Creator</span> and the 
        <span class="highlight">Referrer</span>
      </p>

      <div id="qrContainer" class="qr-container">
        <div class="qr-item">
          <h2 class="qr-title">Creator's Invoice</h2>
          <canvas id="qrcode1"></canvas>
          <p id="status1" class="status not-paid">Awaiting Payment</p>
        </div>
        <div class="qr-item">
          <h2 class="qr-title">Referrer's Invoice</h2>
          <canvas id="qrcode2"></canvas>
          <p id="status2" class="status not-paid">Awaiting Payment</p>
        </div>
      </div>

      <div id="completionMessage" class="completion-message">
        <p>🎉 Payment Successfully Split!</p>
        <p style="font-size: 1.1rem; color: #9ca3af;">
          Both parties have received their share of the payment.
        </p>
        <button class="restart-btn" onclick="location.reload()">Start New Split</button>
      </div>
    </div>

    <script>
      function getQueryParam(param) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(param);
      }

      window.onload = () => {
        // Initialize split inputs
        const creatorSplit = document.getElementById("creatorSplit");
        const referrerSplit = document.getElementById("referrerSplit");
        
        // Get split from URL or use default
        const urlSplit = getQueryParam("split");
        if (urlSplit) {
          const [creator, referrer] = urlSplit.split("/").map(n => parseInt(n.trim()));
          creatorSplit.value = creator;
          referrerSplit.value = referrer;
        }

        // Update split percentage display
        function updateSplitDisplay() {
          document.getElementById("splitPercentage").innerText = 
            
             '55% / 45%';
        }

        // Handle split input changes
        creatorSplit.addEventListener("input", (e) => {
          referrerSplit.value = 100 - parseInt(e.target.value);
          updateSplitDisplay();
        });

        referrerSplit.addEventListener("input", (e) => {
          creatorSplit.value = 100 - parseInt(e.target.value);
          updateSplitDisplay();
        });

        // Initialize QR codes with larger size
        new QRious({
          element: document.getElementById("qrcode1"),
          value: "${invoice1.pr}",
          size: 350,
          background: 'white',
          foreground: '#000000',
          level: 'H'
        });

        new QRious({
          element: document.getElementById("qrcode2"),
          value: "${invoice2.pr}",
          size: 350,
          background: 'white',
          foreground: '#000000',
          level: 'H'
        });

        // Update total amount from URL
        const totalAmount = getQueryParam("amount") || "100 sats";
        document.getElementById("totalAmount").innerText = totalAmount;

        // Check payment status
        async function checkInvoiceStatus(verifyUrl, containerId) {
          try {
            const response = await fetch(verifyUrl);
            const data = await response.json();

            const statusElement = document.getElementById(containerId);
            if (data.settled) {
              statusElement.innerText = "Payment Received ✓";
              statusElement.classList.remove("not-paid");
              statusElement.classList.add("paid");
            }

            // Check if both invoices are paid
            const status1 = document.getElementById("status1").classList.contains("paid");
            const status2 = document.getElementById("status2").classList.contains("paid");
            
            if (status1 && status2) {
              document.getElementById("completionMessage").classList.add("visible");
              document.getElementById("qrContainer").classList.add("hidden");
            }
          } catch (error) {
            console.error(error);
          }
        }

        // Set up interval checks
        setInterval(() => {
          checkInvoiceStatus("${invoice1.verify}", "status1");
          checkInvoiceStatus("${invoice2.verify}", "status2");
        }, 5000);

        // Initial split display update
        updateSplitDisplay();
      };
    </script>
  </body>
</html>  `;
}

function generateInvoiceCard(invoice, index) {
  return `
    <div class="invoice-card bg-gray-800 p-6 rounded-lg shadow-lg transition transform hover:scale-105">
      <h2 class="text-2xl font-semibold text-gray-200 mb-4">Invoice ${index}</h2>
      <canvas id="qrcode${index}" class="mx-auto mb-4"></canvas>
      <p class="text-sm text-gray-400 mb-4">
        Scan this QR code to make the payment.
      </p>
      <p class="font-bold text-lg">
        Status: <span id="status${index}" class="text-yellow-500">Pending</span>
      </p>
    </div>
  `;
}
