
const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10kb' }));

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const keys = new Map();

app.get('/', (_req, res) => {
  res.type('text/plain').send('WIRE-PROXY: servidor online');
});

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) {
    return res.status(503).json({
      error: 'Configure ADMIN_TOKEN nas variáveis de ambiente do Render.'
    });
  }

  const supplied = req.get('x-admin-token') || '';
  const a = Buffer.from(supplied);
  const b = Buffer.from(ADMIN_TOKEN);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Não autorizado' });
  }
  next();
}

app.post('/admin/keys', requireAdmin, (req, res) => {
  const days = Number(req.body && req.body.days);

  if (![1, 7, 30].includes(days)) {
    return res.status(400).json({
      error: 'Validade deve ser 1, 7 ou 30 dias.'
    });
  }

  const key = crypto.randomBytes(16).toString('hex').toUpperCase();
  const expiresAt = Date.now() + days * 24 * 60 * 60 * 1000;

  keys.set(key, { expiresAt, activated: false });

  res.status(201).json({
    key,
    days,
    expiresAt: new Date(expiresAt).toISOString()
  });
});

app.post('/validate', (req, res) => {
  const key = typeof req.body?.key === 'string'
    ? req.body.key.trim().toUpperCase()
    : '';

  const item = keys.get(key);

  if (!item || item.expiresAt <= Date.now()) {
    return res.status(401).json({
      valid: false,
      error: 'Chave inválida ou expirada.'
    });
  }

  item.activated = true;

  res.json({
    valid: true,
    expiresAt: new Date(item.expiresAt).toISOString()
  });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

const port = Number(process.env.PORT) || 3000;

app.listen(port, '0.0.0.0', () => {
  console.log(`WIRE-PROXY online na porta ${port}`);
});
