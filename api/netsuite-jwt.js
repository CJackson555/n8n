import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  const { client_id, account_id } = req.query;

  const rawKey = process.env.PRIVATE_KEY;
  if (!client_id || !account_id || !rawKey) {
    return res.status(400).json({ error: 'Missing required params or key' });
  }

  const privateKey = rawKey.replace(/\\n/g, '\n');

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: client_id,
    scope: 'rest_webservices',
    aud: `https://${account_id.toLowerCase()}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token`,
    iat: now,
    exp: now + 300
  };

  try {
    const token = jwt.sign(payload, privateKey, { algorithm: 'ES256' });
    return res.json({ jwt: token });
  } catch (e) {
    return res.status(500).json({ error: 'JWT signing failed', details: e.message });
  }
}
