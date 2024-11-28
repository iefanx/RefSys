import type { VercelRequest, VercelResponse } from '@vercel/node';
import WebSocket from 'ws';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { relay, filters } = req.query;

  // Validate query parameters
  if (!relay) {
    return res.status(400).json({ error: 'Missing "relay" parameter' });
  }

  const parsedFilters = filters ? JSON.parse(filters as string) : [];

  try {
    // Handle WebSocket communication with a promise
    const response: any = await new Promise((resolve, reject) => {
      const ws = new WebSocket(relay as string);
      const events: any[] = [];
      let lastTimestamp = 0;

      ws.on('open', () => {
        const subscriptionId = Math.random().toString(36).substring(2, 15);
        ws.send(JSON.stringify(['REQ', subscriptionId, ...parsedFilters]));
      });

      ws.on('message', (data) => {
        const message = JSON.parse(data.toString());
        if (message[0] === 'EVENT') {
          const event = message[2];
          events.push(event);
          lastTimestamp = Math.max(lastTimestamp, event.created_at);
        } else if (message[0] === 'EOSE') {
          ws.close();
          events.sort((a, b) => b.created_at - a.created_at); // Sort events by timestamp
          resolve({ events, lastTimestamp });
        }
      });

      ws.on('error', (error) => reject({ error: 'WebSocket error', details: error }));
    });

    // Return the JSON response
    res.status(200).json(response);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error', details: error });
  }
}
