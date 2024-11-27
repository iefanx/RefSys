import type { VercelRequest, VercelResponse } from '@vercel/node';
import { Pool } from 'pg';

// Create a connection pool
const pool = new Pool();

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { npub, eventId } = req.query;

  // Validate input parameters
  if (!npub || !eventId) {
    return res.status(400).json({ error: 'Missing required parameters: npub and eventId.' });
  }

  try {
    // Query the database to check if the user with the provided public key exists
    const userResult = await pool.query(
      `SELECT id FROM users WHERE npub = $1`,
      [npub]
    );

    // If user doesn't exist, return false
    if (userResult.rowCount === 0) {
      return res.status(404).json({ paid: false, message: 'User not found.' });
    }

    const userId = userResult.rows[0].id;

    // Check if the user has purchased the event
    const purchaseResult = await pool.query(
      `SELECT amount, purchased_at FROM event_purchases 
       WHERE user_id = $1 AND event_id = $2`,
      [userId, eventId]
    );

    // If no purchase record is found, return false
    if (purchaseResult.rowCount === 0) {
      return res.status(404).json({ paid: false, message: 'No purchase found for this event.' });
    }

    // Return true with details if a purchase exists
    const purchase = purchaseResult.rows[0];
    return res.status(200).json({
      paid: true,
      message: 'User has paid for this event.',
      details: {
        userId,
        eventId,
        amount: purchase.amount,
        purchasedAt: purchase.purchased_at,
      },
    });
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ error: 'An error occurred while processing the request.' });
  }
}
