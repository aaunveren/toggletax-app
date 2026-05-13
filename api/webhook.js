const crypto = require('crypto');

module.exports = async (req, res) => {
  // Only accept POST
  if (req.method !== 'POST') {
    return res.status(405).end();
  }

  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
  const hmac   = req.headers['x-shopify-hmac-sha256'];

  if (!hmac || !secret) {
    return res.status(401).end();
  }

  // Collect raw body (required for correct HMAC)
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  const rawBody = Buffer.concat(chunks);

  const hash = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('base64');

  if (hash !== hmac) {
    return res.status(401).end();
  }

  return res.status(200).end();
};

module.exports.config = {
  api: { bodyParser: false },
};
