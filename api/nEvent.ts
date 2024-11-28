import type { VercelRequest, VercelResponse } from '@vercel/node';
import WebSocket from 'ws';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Destructure and validate the query parameters
  const { relay = '', filters = '' } = req.query;

  if (!relay || !filters) {
    return res.status(400).json({ error: 'Missing relay or filters' });
  }

  // Parse filters (assume it's passed as a JSON string)
  let parsedFilters;
  try {
    parsedFilters = JSON.parse(filters as string);
  } catch (error) {
    return res.status(400).json({ error: 'Invalid filters format' });
  }

  try {
    // Wrap WebSocket handling in a promise
    const response: any = await new Promise((resolve, reject) => {
      const ws = new WebSocket(relay as string);
      const events: any[] = [];
      let lastTimestamp = 0;

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
            ws.close();
            // Sort events by timestamp before resolving
            events.sort((a, b) => b.created_at - a.created_at);
            resolve({
              events,
              lastTimestamp,
              headers: {
                'Cache-Control': 'public, max-age=3600, s-maxage=3600, must-revalidate',
                'Vary': 'RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept',
                'x-cache-status': 'DYNAMIC',
              },
            });
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      });

      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        reject({ error: 'WebSocket error occurred' });
      });
    });

    // Send the collected events as the response
    res.setHeader('Cache-Control', response.headers['Cache-Control']);
    res.setHeader('Vary', response.headers['Vary']);
    res.setHeader('x-cache-status', response.headers['x-cache-status']);
    res.status(200).json({ events: response.events, lastTimestamp: response.lastTimestamp });
  } catch (error) {
    console.error('Error in handler:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}
