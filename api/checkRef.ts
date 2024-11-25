import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'node:crypto';

interface VerificationStep {
  step: number;
  title: string;
  description: string;
  status: 'pending' | 'complete' | 'success' | 'failed';
  durationMs: number;
}

interface VerificationMetrics {
  totalDurationMs: number;
  steps: VerificationStep[];
  isValid: boolean;
}

class SignatureVerifier {
  private static readonly SIGNING_SECRET_KEY = 'your-secret-signing-key';
  
  private static computeSignature(data: string): { signature: string; durationMs: number } {
    const startTime = performance.now();
    const signature = crypto
      .createHmac('sha256', this.SIGNING_SECRET_KEY)
      .update(data)
      .digest('base64url');
    const endTime = performance.now();
    return { signature, durationMs: endTime - startTime };
  }

  public static verify(eventId: string, publicKey: string, providedSignature: string): VerificationMetrics {
    const startTime = performance.now();
    const metrics: VerificationMetrics = {
      totalDurationMs: 0,
      steps: [],
      isValid: false
    };

    // Step 1: Parameter validation
    const step1Start = performance.now();
    const areParamsValid = Boolean(eventId && publicKey && providedSignature);
    metrics.steps.push({
      step: 1,
      title: "Parameter Validation",
      description: "Validating required parameters",
      status: areParamsValid ? 'success' : 'failed',
      durationMs: performance.now() - step1Start
    });

    if (!areParamsValid) {
      metrics.totalDurationMs = performance.now() - startTime;
      return metrics;
    }

    // Step 2: Data preparation
    const step2Start = performance.now();
    const dataToVerify = `${eventId}|${publicKey}`;
    metrics.steps.push({
      step: 2,
      title: "Data Preparation",
      description: "Preparing signature data",
      status: 'success',
      durationMs: performance.now() - step2Start
    });

    // Step 3: Signature computation
    const step3Start = performance.now();
    const { signature: computedSignature, durationMs: computeDuration } = this.computeSignature(dataToVerify);
    metrics.steps.push({
      step: 3,
      title: "Signature Computation",
      description: "Computing HMAC signature",
      status: 'success',
      durationMs: computeDuration
    });

    // Step 4: Signature verification
    const step4Start = performance.now();
    const isValid = computedSignature === providedSignature;
    metrics.steps.push({
      step: 4,
      title: "Signature Verification",
      description: "Comparing signatures",
      status: isValid ? 'success' : 'failed',
      durationMs: performance.now() - step4Start
    });

    metrics.isValid = isValid;
    metrics.totalDurationMs = performance.now() - startTime;
    return metrics;
  }
}

export default function handler(req: VercelRequest, res: VercelResponse) {
  const { eventID = '', publicKey = '', signature = '' } = req.query;
  const [eventIDString, publicKeyString, signatureString] = [eventID, publicKey, signature].map(
    param => Array.isArray(param) ? param[0] : param
  );

  const verificationMetrics = SignatureVerifier.verify(
    eventIDString,
    publicKeyString,
    signatureString
  );

  const htmlTemplate = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Signature Verification</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
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
          <div class="glassmorphism rounded-xl p-4 sm:p-6 shadow-2xl space-y-4 sm:space-y-6">
            <!-- Header -->
            <div class="flex items-center justify-between fade-in">
              <div>
                <h1 class="text-xl sm:text-2xl font-bold ${verificationMetrics.isValid ? 'text-emerald-400' : 'text-rose-400'}">
                  ${verificationMetrics.isValid ? 'Signature Verified' : 'Verification Failed'}
                </h1>
                <p class="text-xs sm:text-sm text-gray-400 mt-1">
                  Time: ${verificationMetrics.totalDurationMs.toFixed(2)}ms
                </p>
              </div>
              <div class="glassmorphism px-3 sm:px-4 py-2 rounded-full text-xs sm:text-sm">
                <span class="mr-2">Status:</span>
                <span class="${verificationMetrics.isValid ? 'text-emerald-400' : 'text-rose-400'} font-semibold">
                  ${verificationMetrics.isValid ? 'VALID' : 'INVALID'}
                </span>
              </div>
            </div>

            <!-- Verification Process -->
            <div class="fade-in">
              <h2 class="text-lg sm:text-xl font-semibold mb-3 sm:mb-4">Process Steps</h2>
              <div class="space-y-2 sm:space-y-3">
                ${verificationMetrics.steps.map((step, index) => `
                  <div class="glassmorphism rounded-lg p-3 sm:p-4 flex items-start transition-all hover:bg-gray-800/50"
                       style="animation: fadeIn 0.3s ease-out forwards; animation-delay: ${index * 0.1}s">
                    <div class="w-6 h-6 sm:w-8 sm:h-8 rounded-full bg-gray-800 flex items-center justify-center flex-shrink-0 mr-3">
                      <span class="text-xs sm:text-sm font-medium">${step.step}</span>
                    </div>
                    <div class="flex-grow min-w-0">
                      <div class="flex items-center justify-between mb-1">
                        <h3 class="font-medium text-sm sm:text-base truncate">${step.title}</h3>
                        <span class="text-xs text-gray-400 ml-2">${step.durationMs.toFixed(3)}ms</span>
                      </div>
                      <p class="text-xs text-gray-400 truncate">${step.description}</p>
                    </div>
                    <div class="ml-2 sm:ml-3 flex-shrink-0">
                      ${step.status === 'complete' || step.status === 'success'
                        ? '<svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>'
                        : '<svg class="w-5 h-5 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'}
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>

            <!-- Parameters -->
            <div class="fade-in">
              <h2 class="text-lg sm:text-xl font-semibold mb-3 sm:mb-4">Parameters</h2>
              <div class="space-y-2 sm:space-y-3">
                ${[
                  { label: 'Event ID', value: eventIDString },
                  { label: 'Public Key', value: publicKeyString },
                  { label: 'Signature', value: signatureString }
                ].map(({ label, value }) => `
                  <div class="glassmorphism rounded-lg p-3 sm:p-4 transition-all hover:bg-gray-800/50">
                    <h3 class="text-xs sm:text-sm font-medium text-gray-400 mb-1">${label}</h3>
                    <p class="parameter-value font-mono">${value || 'Not provided'}</p>
                  </div>
                `).join('')}
              </div>
            </div>

            ${!verificationMetrics.isValid ? `
              <div class="mt-4 sm:mt-6 bg-rose-950/30 border border-rose-800/50 rounded-lg p-3 sm:p-4 fade-in">
                <div class="flex items-center mb-2 sm:mb-3">
                  <svg class="w-4 h-4 sm:w-5 sm:h-5 text-rose-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                  </svg>
                  <h3 class="text-rose-400 font-semibold text-sm sm:text-base">Security Alert</h3>
                </div>
                <div class="space-y-1 text-xs sm:text-sm text-gray-300">
                  <div class="flex items-center">
                    <span class="text-rose-400 mr-2">•</span>
                    <span>Data tampering detected</span>
                  </div>
                  <div class="flex items-center">
                    <span class="text-rose-400 mr-2">•</span>
                    <span>Invalid/expired signature</span>
                  </div>
                  <div class="flex items-center">
                    <span class="text-rose-400 mr-2">•</span>
                    <span>Incorrect signing key</span>
                  </div>
                </div>
              </div>
            ` : ''}
          </div>
        </div>
      </body>
    </html>
  `;

  return res.status(verificationMetrics.isValid ? 200 : 400).send(htmlTemplate);
}
