/**
 * SERVIDOR SAAS — Portero Virtual
 * Base de datos: PostgreSQL (datos permanentes)
 *
 * Instalación:
 *   npm install express ws web-push pg bcryptjs jsonwebtoken cors dotenv
 */

require('dotenv').config();

const express   = require('express');
const WebSocket = require('ws');
const webPush   = require('web-push');
const { Pool }  = require('pg');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const path      = require('path');
const crypto    = require('crypto');

// ── Configuración ─────────────────────────────────────────
const PORT        = process.env.PORT         || 3000;
const JWT_SECRET  = process.env.JWT_SECRET   || 'cambia_esto';
const VAPID_PUB   = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIV  = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL = process.env.VAPID_EMAIL       || 'mailto:admin@example.com';
const DATABASE_URL = process.env.DATABASE_URL     || '';

if (VAPID_PUB && VAPID_PRIV) {
  webPush.setVapidDetails(VAPID_EMAIL, VAPID_PUB, VAPID_PRIV);
}

// ── PostgreSQL ────────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Crear tablas si no existen
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clients (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      email       TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      plan        TEXT NOT NULL DEFAULT 'basic',
      active      BOOLEAN NOT NULL DEFAULT true,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS portals (
      id          TEXT PRIMARY KEY,
      client_id   TEXT NOT NULL REFERENCES clients(id),
      name        TEXT NOT NULL,
      address     TEXT NOT NULL,
      city        TEXT NOT NULL DEFAULT '',
      active      BOOLEAN NOT NULL DEFAULT true,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS floors (
      id            TEXT PRIMARY KEY,
      portal_id     TEXT NOT NULL REFERENCES portals(id) ON DELETE CASCADE,
      number        TEXT NOT NULL,
      letter        TEXT NOT NULL,
      resident_name TEXT NOT NULL DEFAULT '',
      UNIQUE(portal_id, number, letter)
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id           TEXT PRIMARY KEY,
      portal_id    TEXT NOT NULL REFERENCES portals(id) ON DELETE CASCADE,
      floor_number TEXT NOT NULL,
      floor_letter TEXT NOT NULL,
      subscription TEXT NOT NULL,
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(portal_id, floor_number, floor_letter)
    );

    CREATE TABLE IF NOT EXISTS call_log (
      id           TEXT PRIMARY KEY,
      portal_id    TEXT NOT NULL,
      floor_number TEXT NOT NULL,
      floor_letter TEXT NOT NULL,
      started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      answered     BOOLEAN NOT NULL DEFAULT false,
      duration_sec INTEGER NOT NULL DEFAULT 0
    );
  `);
  log('Base de datos lista');
}

// ── Helpers ───────────────────────────────────────────────
function uid()  { return crypto.randomBytes(8).toString('hex'); }
function log(m) { console.log(`[${new Date().toLocaleTimeString('es')}] ${m}`); }

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Sin token' });
  try {
    req.client = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ── Express ───────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── API: Autenticación ────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Faltan campos' });
  if (password.length < 8) return res.status(400).json({ error: 'Contraseña demasiado corta' });

  const existing = await pool.query('SELECT id FROM clients WHERE email = $1', [email]);
  if (existing.rows.length) return res.status(409).json({ error: 'Email ya registrado' });

  const id   = uid();
  const hash = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO clients (id, name, email, password) VALUES ($1,$2,$3,$4)', [id, name, email, hash]);

  const token = jwt.sign({ id, email, name }, JWT_SECRET, { expiresIn: '30d' });
  log(`Nuevo cliente: ${email}`);
  res.json({ token, client: { id, name, email } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Faltan campos' });

  const result = await pool.query('SELECT * FROM clients WHERE email = $1', [email]);
  const client = result.rows[0];
  if (!client) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const ok = await bcrypt.compare(password, client.password);
  if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  if (!client.active) return res.status(403).json({ error: 'Cuenta suspendida' });

  const token = jwt.sign({ id: client.id, email: client.email, name: client.name }, JWT_SECRET, { expiresIn: '30d' });
  log(`Login: ${email}`);
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, plan: client.plan } });
});

// ── API: Portales ─────────────────────────────────────────

app.get('/api/portals', authMiddleware, async (req, res) => {
  const result = await pool.query(`
    SELECT p.*, COUNT(f.id) as floor_count
    FROM portals p
    LEFT JOIN floors f ON f.portal_id = p.id
    WHERE p.client_id = $1
    GROUP BY p.id
    ORDER BY p.created_at DESC
  `, [req.client.id]);
  res.json(result.rows);
});

app.post('/api/portals', authMiddleware, async (req, res) => {
  const { name, address, city } = req.body;
  if (!name || !address) return res.status(400).json({ error: 'Faltan nombre y dirección' });

  const id = uid();
  await pool.query('INSERT INTO portals (id, client_id, name, address, city) VALUES ($1,$2,$3,$4,$5)',
    [id, req.client.id, name, address, city || '']);
  log(`Portal creado: ${name}`);
  res.json({ id, name, address, city });
});

app.put('/api/portals/:id', authMiddleware, async (req, res) => {
  const portal = await pool.query('SELECT * FROM portals WHERE id = $1 AND client_id = $2', [req.params.id, req.client.id]);
  if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });

  const { name, address, city } = req.body;
  const p = portal.rows[0];
  await pool.query('UPDATE portals SET name=$1, address=$2, city=$3 WHERE id=$4',
    [name || p.name, address || p.address, city ?? p.city, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/portals/:id', authMiddleware, async (req, res) => {
  const portal = await pool.query('SELECT id FROM portals WHERE id = $1 AND client_id = $2', [req.params.id, req.client.id]);
  if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });
  await pool.query('DELETE FROM portals WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ── API: Datos públicos del portal (para el QR) ───────────

app.get('/api/portal/:portalId/public', async (req, res) => {
  const portal = await pool.query('SELECT * FROM portals WHERE id = $1 AND active = true', [req.params.portalId]);
  if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });

  const rows = await pool.query(`
    SELECT number, letter FROM floors
    WHERE portal_id = $1
    ORDER BY CAST(number AS INTEGER), letter
  `, [req.params.portalId]);

  const floorsMap = {};
  rows.rows.forEach(({ number, letter }) => {
    if (!floorsMap[number]) floorsMap[number] = { number, letters: [] };
    floorsMap[number].letters.push(letter);
  });

  const p = portal.rows[0];
  res.json({
    id:      p.id,
    name:    p.name,
    address: p.address,
    city:    p.city,
    floors:  Object.values(floorsMap)
  });
});

// ── API: Pisos ────────────────────────────────────────────

app.get('/api/portals/:portalId/floors', authMiddleware, async (req, res) => {
  const portal = await pool.query('SELECT id FROM portals WHERE id = $1 AND client_id = $2', [req.params.portalId, req.client.id]);
  if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });

  const result = await pool.query(`
    SELECT f.*,
      CASE WHEN ps.id IS NOT NULL THEN true ELSE false END as has_push
    FROM floors f
    LEFT JOIN push_subscriptions ps ON ps.portal_id = f.portal_id
      AND ps.floor_number = f.number AND ps.floor_letter = f.letter
    WHERE f.portal_id = $1
    ORDER BY CAST(f.number AS INTEGER), f.letter
  `, [req.params.portalId]);
  res.json(result.rows);
});

app.post('/api/portals/:portalId/floors', authMiddleware, async (req, res) => {
  const portal = await pool.query('SELECT id FROM portals WHERE id = $1 AND client_id = $2', [req.params.portalId, req.client.id]);
  if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });

  const { number, letter, resident_name } = req.body;
  if (!number || !letter) return res.status(400).json({ error: 'Faltan piso y letra' });

  try {
    const id = uid();
    await pool.query('INSERT INTO floors (id, portal_id, number, letter, resident_name) VALUES ($1,$2,$3,$4,$5)',
      [id, req.params.portalId, number, letter, resident_name || '']);
    res.json({ id, number, letter, resident_name: resident_name || '' });
  } catch {
    res.status(409).json({ error: 'Este piso y letra ya existe en este portal' });
  }
});

app.delete('/api/portals/:portalId/floors/:floorId', authMiddleware, async (req, res) => {
  const portal = await pool.query('SELECT id FROM portals WHERE id = $1 AND client_id = $2', [req.params.portalId, req.client.id]);
  if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });
  await pool.query('DELETE FROM floors WHERE id = $1 AND portal_id = $2', [req.params.floorId, req.params.portalId]);
  res.json({ ok: true });
});

// ── API: Push ─────────────────────────────────────────────

app.post('/api/subscribe', async (req, res) => {
  const { portalId, floorNumber, floorLetter, subscription } = req.body;
  if (!portalId || !floorNumber || !floorLetter || !subscription) return res.status(400).json({ error: 'Faltan datos' });

  const id = uid();
  await pool.query(`
    INSERT INTO push_subscriptions (id, portal_id, floor_number, floor_letter, subscription, updated_at)
    VALUES ($1,$2,$3,$4,$5,NOW())
    ON CONFLICT (portal_id, floor_number, floor_letter)
    DO UPDATE SET subscription = EXCLUDED.subscription, updated_at = NOW()
  `, [id, portalId, floorNumber, floorLetter, JSON.stringify(subscription)]);

  log(`Push registrado: portal=${portalId} piso=${floorNumber}${floorLetter}`);
  res.json({ ok: true });
});

app.get('/api/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUB });
});

// ── API: Estadísticas ─────────────────────────────────────

app.get('/api/portals/:portalId/stats', authMiddleware, async (req, res) => {
  const portal = await pool.query('SELECT id FROM portals WHERE id = $1 AND client_id = $2', [req.params.portalId, req.client.id]);
  if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });

  const stats = await pool.query(`
    SELECT
      COUNT(*) as total_calls,
      SUM(CASE WHEN answered THEN 1 ELSE 0 END) as answered_calls,
      ROUND(AVG(CASE WHEN answered THEN duration_sec END)) as avg_duration_sec
    FROM call_log WHERE portal_id = $1
  `, [req.params.portalId]);

  const recent = await pool.query(`
    SELECT * FROM call_log WHERE portal_id = $1
    ORDER BY started_at DESC LIMIT 20
  `, [req.params.portalId]);

  res.json({ ...stats.rows[0], recent: recent.rows });
});

// ── Servidor HTTP ─────────────────────────────────────────
const server = app.listen(PORT, async () => {
  await initDB();
  log(`Servidor listo en puerto ${PORT}`);
});

// ── WebSocket ─────────────────────────────────────────────
const wss = new WebSocket.Server({ server });
const rooms = new Map();

function getOrCreateRoom(roomId) {
  if (!rooms.has(roomId)) rooms.set(roomId, { visitor: null, neighbor: null, callLogId: null });
  return rooms.get(roomId);
}

function safeSend(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

wss.on('connection', (ws) => {
  ws._room = null;
  ws._role = null;

  ws.on('message', async (data) => {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }

    const { type, room: roomId, portalId: pid } = msg;

    if (type === 'join') {
      const role = msg.role;
      if (!roomId || !role) return;

      const room = getOrCreateRoom(roomId);
      ws._room = roomId;
      ws._role = role;
      room[role] = ws;
      log(`${role} → sala ${roomId}`);

      if (role === 'visitor') {
        const parts       = roomId.split('-');
        const portalId_r  = parts[0];
        const floorNum    = parts[1];
        const floorLetter = parts[2];

        const callLogId = uid();
        room.callLogId  = callLogId;
        await pool.query('INSERT INTO call_log (id, portal_id, floor_number, floor_letter) VALUES ($1,$2,$3,$4)',
          [callLogId, portalId_r, floorNum, floorLetter]);

        const neighborOnline = room.neighbor && room.neighbor.readyState === WebSocket.OPEN;

        if (neighborOnline) {
          safeSend(room.neighbor, { type: 'visitor-calling' });
          safeSend(ws, { type: 'notification-sent' });
          log(`Vecino online → sala ${roomId}`);
        } else {
          const sub = await pool.query(`
            SELECT subscription FROM push_subscriptions
            WHERE portal_id = $1 AND floor_number = $2 AND floor_letter = $3
          `, [portalId_r, floorNum, floorLetter]);

          if (sub.rows.length && VAPID_PUB) {
            try {
              await webPush.sendNotification(JSON.parse(sub.rows[0].subscription), JSON.stringify({
                title: '🔔 Alguien llama al portal',
                body:  'Hay una visita esperando. Pulsa para contestar.',
                url:   `/vecino.html?portal=${portalId_r}&contestar=true`,
                room:  roomId
              }));
              safeSend(ws, { type: 'notification-sent' });
              log(`Push enviado → sala ${roomId}`);
            } catch (err) {
              log(`Error push: ${err.message}`);
              if (err.statusCode === 410) {
                await pool.query('DELETE FROM push_subscriptions WHERE portal_id=$1 AND floor_number=$2 AND floor_letter=$3',
                  [portalId_r, floorNum, floorLetter]);
              }
              safeSend(ws, { type: 'busy' });
            }
          } else {
            safeSend(ws, { type: 'busy' });
          }
        }
      }
    }

    if (type === 'neighbor-ready') {
      const room = rooms.get(roomId);
      if (!room) return;
      safeSend(room.visitor, { type: 'neighbor-ready' });
      if (room.callLogId) {
        await pool.query('UPDATE call_log SET answered=true WHERE id=$1', [room.callLogId]);
      }
    }

    if (type === 'offer') {
      const room = rooms.get(roomId);
      if (room) safeSend(room.neighbor, { type: 'offer', sdp: msg.sdp });
    }

    if (type === 'answer') {
      const room = rooms.get(roomId);
      if (room) safeSend(room.visitor, { type: 'answer', sdp: msg.sdp });
    }

    if (type === 'ice') {
      const room = rooms.get(roomId);
      if (!room) return;
      const target = ws._role === 'visitor' ? room.neighbor : room.visitor;
      safeSend(target, { type: 'ice', candidate: msg.candidate });
    }

    if (type === 'busy') {
      const room = rooms.get(roomId);
      if (room) safeSend(room.visitor, { type: 'busy' });
    }

    if (type === 'hangup') {
      const room = rooms.get(roomId);
      if (!room) return;
      const other = ws._role === 'visitor' ? room.neighbor : room.visitor;
      safeSend(other, { type: 'hangup' });
      if (room.callLogId && msg.duration) {
        await pool.query('UPDATE call_log SET duration_sec=$1 WHERE id=$2',
          [Math.round(msg.duration), room.callLogId]);
      }
    }
  });

  ws.on('close', () => {
    const { _room: roomId, _role: role } = ws;
    if (!roomId || !role) return;
    const room = rooms.get(roomId);
    if (!room) return;
    const other = role === 'visitor' ? room.neighbor : room.visitor;
    safeSend(other, { type: 'hangup' });
    room[role] = null;
    if (!room.visitor && !room.neighbor) rooms.delete(roomId);
  });

  ws.on('error', err => console.error('WS error:', err.message));
});

setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.ping();
  });
}, 30000);
