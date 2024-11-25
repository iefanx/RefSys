import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'node:crypto';

// Constants for configuration
const CONFIG = {
  SIGNING_SECRET_KEY: 'your-secret-signing-key', // For testing only
  MAX_URL_LENGTH: 2048,
  ERROR_MESSAGES: {
    MISSING_PARAMS: 'Missing required parameters: eventID or publicKey',
    URL_TOO_LONG: 'Generated URL exceeds maximum length',
  }
} as const;

class ReferralManager {
  private readonly signingKey: string;

  constructor(signingKey: string) {
    this.signingKey = signingKey;
  }

  // Generate HMAC signature
  private sign(data: string): string {
    return crypto
      .createHmac('sha256', this.signingKey)
      .update(data)
      .digest('base64url');
  }

  // Generate referral URL with signature
  public generateReferralUrl(eventID: string, publicKey: string): string {
    const dataToSign = `${eventID}|${publicKey}`;
    const signature = this.sign(dataToSign);

    return new URL('https://lnwall-iefans-projects.vercel.app/api/checkRef')
      .toString() + `?eventID=${eventID}&publicKey=${publicKey}&signature=${signature}`;
  }

  // Validate request parameters
  public validateRequest(req: VercelRequest): string | null {
    const { eventID, publicKey } = req.query;
    
    if (!eventID || !publicKey) {
      return CONFIG.ERROR_MESSAGES.MISSING_PARAMS;
    }

    return null;
  }
}

export default function handler(req: VercelRequest, res: VercelResponse) {
  const referralManager = new ReferralManager(CONFIG.SIGNING_SECRET_KEY);
  const validationError = referralManager.validateRequest(req);

  if (validationError) {
    return res.send(generateErrorHTML(validationError));
  }

  const eventID = Array.isArray(req.query.eventID) ? req.query.eventID[0] : req.query.eventID || '';
  const publicKey = Array.isArray(req.query.publicKey) ? req.query.publicKey[0] : req.query.publicKey || '';
  
  const referralUrl = referralManager.generateReferralUrl(eventID, publicKey);

  if (referralUrl.length > CONFIG.MAX_URL_LENGTH) {
    return res.send(generateErrorHTML(CONFIG.ERROR_MESSAGES.URL_TOO_LONG));
  }

  return res.send(generateSuccessHTML(referralUrl));
}

// HTML Generation Functions
function generateSuccessHTML(referralUrl: string): string {
  return `


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Referral Link Generated</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">

<style>
          @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
          }
          .fade-in {
            animation: fadeIn 0.3s ease-out forwards;
          }
          .parameter-value {
            word-break: break-all;
            max-width: 100%;
            display: inline-block;
          }
          .glassmorphism {
            background: rgba(17, 24, 39, 0.7);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(255, 255, 255, 0.1);
          }
          @media (max-width: 640px) {
            .container { padding: 0.5rem; }
            .parameter-value { font-size: 0.75rem; }
          }
        </style>

</head>
<body class="bg-[#0a0a0a] text-gray-100 min-h-screen">
    <div class="container mx-auto px-2 sm:px-4 py-4 sm:py-8 max-w-4xl">
        <div class="max-w-4xl mx-auto">
            <div class="glassmorphism rounded-xl p-4 sm:p-6 shadow-2xl space-y-4 sm:space-y-6">
                <div class="text-center mb-6 sm:mb-8">
                    <i class="fas fa-link text-blue-500 text-2xl sm:text-2xl mb-3"></i>
                    <h1 class="text-xl sm:text-lg font-bold bg-gradient-to-r from-blue-500 to-purple-500 bg-clip-text text-transparent">
                        Referral Link Generated
                    </h1>
                </div>

                <div class="space-y-4 sm:space-y-6">
                    <!-- Security Features - Compact on mobile -->
                    <div class="glassmorphism px-3 sm:px-4 py-2 rounded-lg text-xs sm:text-sm">
                        <h2 class="text-lg sm:text-xl font-semibold mb-2 sm:mb-4 flex items-center">
                            <i class="fas fa-shield-alt text-green-500 mr-2"></i>
                            Security Features
                        </h2>
                        <ul class="list-disc list-inside space-y-1 sm:space-y-2 text-sm sm:text-base text-gray-300">
                            <li>HMAC-SHA256 Digital Signature</li>
                            <li>Tamper-proof Design</li>
                            <li>URL Parameter Validation</li>
                        </ul>
                    </div>

                    <!-- Referral URL Section - Improved copy functionality -->
                    <div class="glassmorphism px-3 sm:px-4 py-2 hidden rounded-lg text-xs sm:text-sm">
                        <h2 class="text-lg sm:text-xl font-semibold mb-2 sm:mb-4 flex items-center">
                            <i class="fas fa-link text-blue-500 mr-2"></i>
                            Your Referral URL
                            <span class="ml-2 text-xs sm:text-sm text-gray-400">(Tap to copy)</span>
                        </h2>
                        <div class="relative">
                            <div id="urlContainer " 
                                 class="bg-gray-950 hidden rounded-lg p-3 sm:p-4 break-all text-gray-300 font-mono text-xs sm:text-sm cursor-pointer hover:bg-gray-900 transition-colors duration-200 mb-2 sm:mb-0"
                                 onclick="copyToClipboard('${referralUrl}')">
                                ${referralUrl}
                            </div>
                            <button 
                                onclick="copyToClipboard('${referralUrl}')"
                                class="w-full sm:w-auto sm:absolute sm:right-2 sm:top-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all duration-200 flex items-center justify-center">
                                <i class="fas fa-copy font-semibold mr-2"></i>
                                Copy URL
                            </button>
                        </div>
                    </div>

                    <!-- QR Code Section - Compact on mobile -->
                    <div class="glassmorphism px-3 sm:px-4 py-2 rounded-lg text-xs sm:text-sm">
                        <h2 class="text-lg sm:text-xl font-semibold mb-3 flex items-center">
                            <i class="fas fa-qrcode text-purple-500 mr-2"></i>
                            QR Code
                        </h2>
                        <div class="flex justify-center">
                            <div class="bg-white p-2 rounded-lg shadow-lg">
                                <img 
                                    src="https://api.qrserver.com/v1/create-qr-code/?size=350x350&data=${encodeURIComponent(referralUrl)}"
                                    alt="QR Code"
                                    class="w-52 h-52 sm:w-52 sm:h-52"
                                />
                            </div>
                        </div>
                        <p class="text-center mt-3 text-gray-400 text-xs sm:text-sm">
                            Scan with your mobile device
                        </p>
                    </div>

                    <!-- Action Button - Full width on mobile -->
                    <div class="flex justify-center mt-6">
                        <a 
                            href="${referralUrl}" 
                            target="_blank"
                            class="w-full sm:w-auto px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all duration-200 flex items-center justify-center">
                            <i class="fas fa-external-link-alt font-semibold mr-2"></i>
                            Open Link
                        </a>
                    </div>
                </div>
            </div>

            <div class="text-center mt-6 text-gray-400">
                <p class="text-xs sm:text-sm">
                    <i class="fas fa-info-circle mr-1"></i>
                    This link includes a secure signature to prevent tampering
                </p>
            </div>
        </div>
    </div>

    <script>
    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            const btn = document.querySelector('button');
            const urlContainer = document.getElementById('urlContainer');
            const originalBtnContent = btn.innerHTML;
            
            // Update button appearance
            btn.innerHTML = '<i class="fas fa-check mr-2"></i>Copied!';
            btn.classList.add('from-green-600', 'to-green-700');
            btn.classList.remove('from-blue-600', 'to-purple-600');
            
            // Add success message
            const message = document.createElement('div');
            message.className = 'fixed bottom-4 left-1/2 transform -translate-x-1/2 bg-green-500 text-white px-6 py-3 rounded-lg shadow-lg flex items-center justify-center text-sm transition-all duration-300 z-50';
            message.innerHTML = '<i class="fas fa-check-circle mr-2"></i>URL copied to clipboard!';
            document.body.appendChild(message);
            
            // Reset after delay
            setTimeout(() => {
                btn.innerHTML = originalBtnContent;
                btn.classList.remove('from-green-600', 'to-green-700');
                btn.classList.add('from-blue-600', 'to-purple-600');
                message.style.opacity = '0';
                setTimeout(() => message.remove(), 300);
            }, 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
            const message = document.createElement('div');
            message.className = 'fixed bottom-4 left-1/2 transform -translate-x-1/2 bg-red-500 text-white px-6 py-3 rounded-lg shadow-lg text-sm';
            message.innerHTML = '<i class="fas fa-times-circle mr-2"></i>Failed to copy URL';
            document.body.appendChild(message);
            setTimeout(() => {
                message.style.opacity = '0';
                setTimeout(() => message.remove(), 300);
            }, 3000);
        }
    }
    </script>
</body>
</html>  `;
}
