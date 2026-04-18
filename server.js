/**
 * SERVIDOR SAAS — Portero Virtual
 * ================================
 * Multi-portal, con base de datos, API REST y señalización WebRTC.
 *
 * Instalación:
 *   npm install express ws web-push better-sqlite3 bcryptjs jsonwebtoken cors dotenv
 *
 * Variables de entorno (.env):
 *   PORT=3000
 *   JWT_SECRET=una_clave_secreta_larga
 *   VAPID_PUBLIC_KEY=...
 *   VAPID_PRIVATE_KEY=...
 *   VAPID_EMAIL=mailto:admin@tudominio.com
 *
 * Generar claves VAPID (solo una vez):
 *   node -e "const wp=require('web-push');console.log(JSON.stringify(wp.generateVAPIDKeys(),null,2))"
 */

require('dotenv').config();

const express    = require('express');
const WebSocket  = require('ws');
const webPush    = require('web-push');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const crypto     = require('crypto');

// ── Configuración ─────────────────────────────────────────────────────────
const PORT         = process.env.PORT         || 3000;
const JWT_SECRET   = process.env.JWT_SECRET   || 'cambia_esto_por_algo_seguro';
const VAPID_PUB    = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIV   = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL  = process.env.VAPID_EMAIL       || 'mailto:admin@example.com';

if (VAPID_PUB && VAPID_PRIV) {
  webPush.setVapidDetails(VAPID_EMAIL, VAPID_PUB, VAPID_PRIV);
}

// ── Base de datos (SQLite — archivo portero.db) ───────────────────────────
const db = new Database('portero.db');
db.pragma('journal_mode = WAL');

// Crear tablas si no existen
db.exec(`
  -- Clientes (administradores de fincas o propietarios)
  CREATE TABLE IF NOT EXISTS clients (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    plan        TEXT NOT NULL DEFAULT 'basic',
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Portales (comunidades de vecinos)
  CREATE TABLE IF NOT EXISTS portals (
    id          TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL REFERENCES clients(id),
    name        TEXT NOT NULL,
    address     TEXT NOT NULL,
    city        TEXT NOT NULL DEFAULT '',
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Pisos de cada portal
  CREATE TABLE IF NOT EXISTS floors (
    id          TEXT PRIMARY KEY,
    portal_id   TEXT NOT NULL REFERENCES portals(id) ON DELETE CASCADE,
    number      TEXT NOT NULL,
    letter      TEXT NOT NULL,
    resident_name TEXT NOT NULL DEFAULT '',
    UNIQUE(portal_id, number, letter)
  );

  -- Suscripciones push de cada vecino
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id           TEXT PRIMARY KEY,
    portal_id    TEXT NOT NULL REFERENCES portals(id) ON DELETE CASCADE,
    floor_number TEXT NOT NULL,
    floor_letter TEXT NOT NULL,
    subscription TEXT NOT NULL,
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(portal_id, floor_number, floor_letter)
  );

  -- Historial de llamadas
  CREATE TABLE IF NOT EXISTS call_log (
    id           TEXT PRIMARY KEY,
    portal_id    TEXT NOT NULL,
    floor_number TEXT NOT NULL,
    floor_letter TEXT NOT NULL,
    started_at   TEXT NOT NULL DEFAULT (datetime('now')),
    answered     INTEGER NOT NULL DEFAULT 0,
    duration_sec INTEGER NOT NULL DEFAULT 0
  );
`);

// ── Express ───────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── Helpers ───────────────────────────────────────────────────────────────
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

// ── API: Autenticación ────────────────────────────────────────────────────

// Registro de nuevo cliente
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Faltan campos' });
  if (password.length < 8) return res.status(400).json({ error: 'Contraseña demasiado corta' });

  const existing = db.prepare('SELECT id FROM clients WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email ya registrado' });

  const id   = uid();
  const hash = await bcrypt.hash(password, 10);
  db.prepare('INSERT INTO clients (id, name, email, password) VALUES (?,?,?,?)').run(id, name, email, hash);

  const token = jwt.sign({ id, email, name }, JWT_SECRET, { expiresIn: '30d' });
  log(`Nuevo cliente: ${email}`);
  res.json({ token, client: { id, name, email } });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Faltan campos' });

  const client = db.prepare('SELECT * FROM clients WHERE email = ?').get(email);
  if (!client) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const ok = await bcrypt.compare(password, client.password);
  if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  if (!client.active) return res.status(403).json({ error: 'Cuenta suspendida' });

  const token = jwt.sign({ id: client.id, email: client.email, name: client.name }, JWT_SECRET, { expiresIn: '30d' });
  log(`Login: ${email}`);
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, plan: client.plan } });
});

// ── API: Portales ─────────────────────────────────────────────────────────

// Listar portales del cliente
app.get('/api/portals', authMiddleware, (req, res) => {
  const portals = db.prepare(`
    SELECT p.*, COUNT(f.id) as floor_count
    FROM portals p
    LEFT JOIN floors f ON f.portal_id = p.id
    WHERE p.client_id = ?
    GROUP BY p.id
    ORDER BY p.created_at DESC
  `).all(req.client.id);
  res.json(portals);
});

// Crear portal
app.post('/api/portals', authMiddleware, (req, res) => {
  const { name, address, city } = req.body;
  if (!name || !address) return res.status(400).json({ error: 'Faltan nombre y dirección' });

  const id = uid();
  db.prepare('INSERT INTO portals (id, client_id, name, address, city) VALUES (?,?,?,?,?)').run(id, req.client.id, name, address, city || '');
  log(`Portal creado: ${name} (${address})`);
  res.json({ id, name, address, city });
});

// Actualizar portal
app.put('/api/portals/:id', authMiddleware, (req, res) => {
  const portal = db.prepare('SELECT * FROM portals WHERE id = ? AND client_id = ?').get(req.params.id, req.client.id);
  if (!portal) return res.status(404).json({ error: 'Portal no encontrado' });

  const { name, address, city } = req.body;
  db.prepare('UPDATE portals SET name=?, address=?, city=? WHERE id=?').run(name || portal.name, address || portal.address, city ?? portal.city, req.params.id);
  res.json({ ok: true });
});

// Eliminar portal
app.delete('/api/portals/:id', authMiddleware, (req, res) => {
  const portal = db.prepare('SELECT * FROM portals WHERE id = ? AND client_id = ?').get(req.params.id, req.client.id);
  if (!portal) return res.status(404).json({ error: 'Portal no encontrado' });
  db.prepare('DELETE FROM portals WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── API: Datos públicos del portal (para el QR del visitante) ─────────────
// Esta ruta NO requiere autenticación — la usa el visitante al escanear el QR
app.get('/api/portal/:portalId/public', (req, res) => {
  const portal = db.prepare('SELECT * FROM portals WHERE id = ? AND active = 1').get(req.params.portalId);
  if (!portal) return res.status(404).json({ error: 'Portal no encontrado' });

  // Agrupar pisos: [{number:'1', letters:['A','B']}, ...]
  const rows = db.prepare(`
    SELECT number, letter FROM floors
    WHERE portal_id = ?
    ORDER BY CAST(number AS INTEGER), letter
  `).all(req.params.portalId);

  const floorsMap = {};
  rows.forEach(({ number, letter }) => {
    if (!floorsMap[number]) floorsMap[number] = { number, letters: [] };
    floorsMap[number].letters.push(letter);
  });

  res.json({
    id:      portal.id,
    name:    portal.name,
    address: portal.address,
    city:    portal.city,
    floors:  Object.values(floorsMap)
  });
});

// ── API: Pisos ────────────────────────────────────────────────────────────

// Listar pisos de un portal
app.get('/api/portals/:portalId/floors', authMiddleware, (req, res) => {
  const portal = db.prepare('SELECT id FROM portals WHERE id = ? AND client_id = ?').get(req.params.portalId, req.client.id);
  if (!portal) return res.status(404).json({ error: 'Portal no encontrado' });

  const floors = db.prepare(`
    SELECT f.*,
      CASE WHEN ps.id IS NOT NULL THEN 1 ELSE 0 END as has_push
    FROM floors f
    LEFT JOIN push_subscriptions ps ON ps.portal_id = f.portal_id
      AND ps.floor_number = f.number AND ps.floor_letter = f.letter
    WHERE f.portal_id = ?
    ORDER BY CAST(f.number AS INTEGER), f.letter
  `).all(req.params.portalId);

  res.json(floors);
});

// Añadir piso
app.post('/api/portals/:portalId/floors', authMiddleware, (req, res) => {
  const portal = db.prepare('SELECT id FROM portals WHERE id = ? AND client_id = ?').get(req.params.portalId, req.client.id);
  if (!portal) return res.status(404).json({ error: 'Portal no encontrado' });

  const { number, letter, resident_name } = req.body;
  if (!number || !letter) return res.status(400).json({ error: 'Faltan piso y letra' });

  try {
    const id = uid();
    db.prepare('INSERT INTO floors (id, portal_id, number, letter, resident_name) VALUES (?,?,?,?,?)').run(id, req.params.portalId, number, letter, resident_name || '');
    res.json({ id, number, letter, resident_name: resident_name || '' });
  } catch {
    res.status(409).json({ error: 'Este piso y letra ya existe en este portal' });
  }
});

// Eliminar piso
app.delete('/api/portals/:portalId/floors/:floorId', authMiddleware, (req, res) => {
  const portal = db.prepare('SELECT id FROM portals WHERE id = ? AND client_id = ?').get(req.params.portalId, req.client.id);
  if (!portal) return res.status(404).json({ error: 'Portal no encontrado' });
  db.prepare('DELETE FROM floors WHERE id = ? AND portal_id = ?').run(req.params.floorId, req.params.portalId);
  res.json({ ok: true });
});

// ── API: Push ─────────────────────────────────────────────────────────────
app.post('/api/subscribe', (req, res) => {
  const { portalId, floorNumber, floorLetter, subscription } = req.body;
  if (!portalId || !floorNumber || !floorLetter || !subscription) return res.status(400).json({ error: 'Faltan datos' });

  const id = uid();
  db.prepare(`
    INSERT INTO push_subscriptions (id, portal_id, floor_number, floor_letter, subscription, updated_at)
    VALUES (?,?,?,?,?,datetime('now'))
    ON CONFLICT(portal_id, floor_number, floor_letter)
    DO UPDATE SET subscription=excluded.subscription, updated_at=excluded.updated_at
  `).run(id, portalId, floorNumber, floorLetter, JSON.stringify(subscription));

  log(`Push registrado: portal=${portalId} piso=${floorNumber}${floorLetter}`);
  res.json({ ok: true });
});

app.get('/api/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUB });
});

// ── API: Estadísticas ─────────────────────────────────────────────────────
app.get('/api/portals/:portalId/stats', authMiddleware, (req, res) => {
  const portal = db.prepare('SELECT id FROM portals WHERE id = ? AND client_id = ?').get(req.params.portalId, req.client.id);
  if (!portal) return res.status(404).json({ error: 'Portal no encontrado' });

  const stats = db.prepare(`
    SELECT
      COUNT(*) as total_calls,
      SUM(answered) as answered_calls,
      ROUND(AVG(CASE WHEN answered=1 THEN duration_sec END)) as avg_duration_sec,
      COUNT(DISTINCT floor_number||floor_letter) as active_floors
    FROM call_log WHERE portal_id = ?
  `).get(req.params.portalId);

  const recent = db.prepare(`
    SELECT * FROM call_log WHERE portal_id = ?
    ORDER BY started_at DESC LIMIT 20
  `).all(req.params.portalId);

  res.json({ ...stats, recent });
});

// ── Servidor HTTP ─────────────────────────────────────────────────────────
const server = app.listen(PORT, () => log(`Servidor HTTP en puerto ${PORT}`));

// ── WebSocket (señalización WebRTC) ───────────────────────────────────────
const wss = new WebSocket.Server({ server });

// rooms: Map de roomId → { visitor: ws|null, neighbor: ws|null, callLogId: string|null }
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

      // Verificar que el portal existe y está activo
      if (pid) {
        const portal = db.prepare('SELECT id, active FROM portals WHERE id = ?').get(pid);
        if (!portal || !portal.active) {
          safeSend(ws, { type: 'error', message: 'Portal inactivo o no encontrado' });
          return;
        }
      }

      const room = getOrCreateRoom(roomId);
      ws._room = roomId;
      ws._role = role;
      room[role] = ws;

      log(`${role} → sala ${roomId}`);

      if (role === 'visitor') {
        // Parsear: portalId-floor-letter
        const parts = roomId.split('-');
        const portalId_room = parts[0];
        const floorNum = parts[1];
        const floorLetter = parts[2];

        // Registrar llamada en el log
        const callLogId = uid();
        room.callLogId = callLogId;
        db.prepare('INSERT INTO call_log (id, portal_id, floor_number, floor_letter) VALUES (?,?,?,?)').run(callLogId, portalId_room, floorNum, floorLetter);

        const neighborOnline = room.neighbor && room.neighbor.readyState === WebSocket.OPEN;

        if (neighborOnline) {
          safeSend(room.neighbor, { type: 'visitor-calling' });
          safeSend(ws, { type: 'notification-sent' });
          log(`Vecino online — sala ${roomId}`);
        } else {
          // Enviar notificación push
          const sub = db.prepare(`
            SELECT subscription FROM push_subscriptions
            WHERE portal_id = ? AND floor_number = ? AND floor_letter = ?
          `).get(portalId_room, floorNum, floorLetter);

          if (sub && VAPID_PUB) {
            try {
              await webPush.sendNotification(JSON.parse(sub.subscription), JSON.stringify({
                title: '🔔 Alguien llama al portal',
                body: 'Hay una visita esperando. Pulsa para contestar.',
                url: `/vecino.html?portal=${portalId_room}&contestar=true`,
                room: roomId
              }));
              safeSend(ws, { type: 'notification-sent' });
              log(`Push enviado → sala ${roomId}`);
            } catch (err) {
              log(`Error push sala ${roomId}: ${err.message}`);
              if (err.statusCode === 410) {
                db.prepare('DELETE FROM push_subscriptions WHERE portal_id = ? AND floor_number = ? AND floor_letter = ?').run(portalId_room, floorNum, floorLetter);
              }
              safeSend(ws, { type: 'busy' });
            }
          } else {
            log(`Sin push en sala ${roomId}`);
            safeSend(ws, { type: 'busy' });
          }
        }
      }
    }

    if (type === 'neighbor-ready') {
      const room = rooms.get(roomId);
      if (!room) return;
      safeSend(room.visitor, { type: 'neighbor-ready' });
      // Marcar llamada como contestada
      if (room.callLogId) {
        db.prepare('UPDATE call_log SET answered=1 WHERE id=?').run(room.callLogId);
      }
      log(`Vecino aceptó → sala ${roomId}`);
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
      // Guardar duración si hay log
      if (room.callLogId && msg.duration) {
        db.prepare('UPDATE call_log SET duration_sec=? WHERE id=?').run(Math.round(msg.duration), room.callLogId);
      }
      log(`Llamada finalizada → sala ${roomId}`);
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
    log(`${role} desconectado → sala ${roomId}`);
  });

  ws.on('error', err => console.error('WS error:', err.message));
});

// Ping keep-alive
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.ping();
  });
}, 30000);

log('Listo. Portales activos: ' + db.prepare('SELECT COUNT(*) as n FROM portals WHERE active=1').get().n);
