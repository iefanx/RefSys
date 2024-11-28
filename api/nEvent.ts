import type { VercelRequest, VercelResponse } from '@vercel/node';
import WebSocket from 'ws';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { relay, filters } = req.query;

  // Validate query parameters
  if (!relay) {
    return res.status(400).json({ error: 'Missing "relay" parameter' });
  }

  let parsedFilters: any;
  try {
    parsedFilters = filters ? JSON.parse(filters as string) : [];
  } catch (error) {
    return res.status(400).json({ error: 'Invalid "filters" parameter' });
  }

  try {
    // WebSocket response handler with timeout
    const response: any = await new Promise((resolve, reject) => {
      const ws = new WebSocket(relay as string);
      const events: any[] = [];
      let lastTimestamp = 0;

      // Set a timeout for WebSocket operations (e.g., 10 seconds)
      const timeout = setTimeout(() => {
        ws.close();
        reject({ error: 'Request timed out' });
      }, 10000);

      ws.on('open', () => {
        const subscriptionId = Math.random().toString(36).substring(2, 15);
        ws.send(JSON.stringify(['REQ', subscriptionId, ...parsedFilters]));
      });

      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          if (message[0] === 'EVENT') {
            const event = message[2];
            events.push(event);
            lastTimestamp = Math.max(lastTimestamp, event.created_at);
          } else if (message[0] === 'EOSE') {
            clearTimeout(timeout);
            ws.close();
            events.sort((a, b) => b.created_at - a.created_at); // Sort events by timestamp
            resolve({ events, lastTimestamp });
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      });

      ws.on('error', (error) => {
        clearTimeout(timeout);
        reject({ error: 'WebSocket error occurred', details: error });
      });

      ws.on('close', () => {
        clearTimeout(timeout);
        if (events.length === 0) {
          reject({ error: 'No events received from the relay' });
        }
      });
    });

    // Return the JSON response
    res.status(200).json(response);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error', details: error });
  }
}
