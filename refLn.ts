import crypto from 'node:crypto';
import { VercelRequest, VercelResponse } from '@vercel/node';

const CONFIG = {
  SIGNING_SECRET_KEY: 'your-secret-signing-key', // Replace with a secure key in production
  MAX_URL_LENGTH: 2048,
  ERROR_MESSAGES: {
    MISSING_PARAMS: 'Missing required parameters: lightning addresses, price, or split percentage.',
    URL_TOO_LONG: 'Generated URL exceeds maximum length.',
  },
} as const;

class ReferralManager {
  private readonly signingKey: string;

  constructor(signingKey: string) {
    this.signingKey = signingKey;
  }

  // Generate HMAC signature for data
  private sign(data: string): string {
    return crypto
      .createHmac('sha256', this.signingKey)
      .update(data)
      .digest('base64url');
  }

  // Generate referral URL
  public generateReferralUrl(
    address1: string,
    address2: string,
    totalPrice: string,
    splitPercentage: string
  ): string {
    const dataToSign = `${address1}|${address2}|${totalPrice}|${splitPercentage}`;
    const signature = this.sign(dataToSign);

    const url = new URL('https://lnwall-iefans-projects.vercel.app/api/refLnCheck');
    url.searchParams.append('address1', address1);
    url.searchParams.append('address2', address2);
    url.searchParams.append('price', totalPrice);
    url.searchParams.append('split', splitPercentage);
    url.searchParams.append('signature', signature);

    return url.toString();
  }

  // Validate request parameters
  public validateRequest(req: VercelRequest): string | null {
    const { address1, address2, price, split } = req.query;

    if (!address1 || !address2 || !price || !split) {
      return CONFIG.ERROR_MESSAGES.MISSING_PARAMS;
    }

    return null;
  }
}

// API Handler
export default function handler(req: VercelRequest, res: VercelResponse) {
  const referralManager = new ReferralManager(CONFIG.SIGNING_SECRET_KEY);
  const validationError = referralManager.validateRequest(req);

  if (validationError) {
    return res.status(400).send({ error: validationError });
  }

  const address1 = Array.isArray(req.query.address1) ? req.query.address1[0] : req.query.address1 || '';
  const address2 = Array.isArray(req.query.address2) ? req.query.address2[0] : req.query.address2 || '';
  const price = Array.isArray(req.query.price) ? req.query.price[0] : req.query.price || '';
  const split = Array.isArray(req.query.split) ? req.query.split[0] : req.query.split || '';

  const referralUrl = referralManager.generateReferralUrl(address1, address2, price, split);

  if (referralUrl.length > CONFIG.MAX_URL_LENGTH) {
    return res.status(400).send({ error: CONFIG.ERROR_MESSAGES.URL_TOO_LONG });
  }

  return res.status(200).send({ referralUrl });
}
