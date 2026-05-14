'use strict';
const crypto = require('crypto');

/** Read raw body as Buffer (stream-safe, no pre-parsing) */
function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) =>
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
    );
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  // Health-check (Shopify may GET the URL to confirm it resolves)
  if (req.method === 'GET' || req.method === 'HEAD') {
    return res.status(200).json({ status: 'ok' });
  }

  if (req.method !== 'POST') {
    return res.status(405).end();
  }

  const secret     = process.env.SHOPIFY_WEBHOOK_SECRET;
  const hmacHeader = req.headers['x-shopify-hmac-sha256'];

  if (!secret) {
    console.error('[ToggleTax] SHOPIFY_WEBHOOK_SECRET env var is not set');
    return res.status(500).end();
  }

  if (!hmacHeader) {
    return res.status(401).json({ error: 'Missing X-Shopify-Hmac-Sha256 header' });
  }

  try {
    const rawBody = await getRawBody(req);

    const computed = crypto
      .createHmac('sha256', secret)
      .update(rawBody)
      .digest('base64');

    const a = Buffer.from(computed);
    const b = Buffer.from(hmacHeader);

    // timingSafeEqual requires identical lengths
    const valid =
      a.length === b.length && crypto.timingSafeEqual(a, b);

    if (!valid) {
      console.warn('[ToggleTax] HMAC mismatch – possible replay or wrong secret');
      return res.status(401).json({ error: 'HMAC verification failed' });
    }

    // Compliance webhook accepted
    return res.status(200).json({ status: 'ok' });
  } catch (err) {
    console.error('[ToggleTax] Webhook error:', err);
    return res.status(500).end();
  }
};
