/**
 * SERVIDOR SAAS — Portero Virtual
 * Fase 2: Panel de administración completo
 * Base de datos: PostgreSQL (datos permanentes)
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

const PORT        = process.env.PORT              || 3000;
const JWT_SECRET  = process.env.JWT_SECRET        || 'cambia_esto';
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
      unit_label    TEXT,
      resident_name TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id          TEXT PRIMARY KEY,
      portal_id   TEXT NOT NULL REFERENCES portals(id) ON DELETE CASCADE,
      floor_id    TEXT NOT NULL REFERENCES floors(id) ON DELETE CASCADE,
      subscription TEXT NOT NULL,
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(floor_id)
    );

    CREATE TABLE IF NOT EXISTS call_log (
      id           TEXT PRIMARY KEY,
      portal_id    TEXT NOT NULL,
      floor_id     TEXT,
      floor_label  TEXT NOT NULL DEFAULT '',
      started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      answered     BOOLEAN NOT NULL DEFAULT false,
      duration_sec INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS notices (
      id               TEXT PRIMARY KEY,
      portal_id        TEXT NOT NULL REFERENCES portals(id) ON DELETE CASCADE,
      type             TEXT NOT NULL DEFAULT 'general',
      title            TEXT NOT NULL,
      body             TEXT NOT NULL,
      sent_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      recipients_count INTEGER NOT NULL DEFAULT 0
    );
  `);

  // Migración: ajustar tabla floors al nuevo esquema
  const migrations = [
    // Añadir columnas nuevas
    "ALTER TABLE floors ADD COLUMN IF NOT EXISTS unit_label TEXT",
    "ALTER TABLE floors ADD COLUMN IF NOT EXISTS resident_name TEXT NOT NULL DEFAULT ''",
    // Quitar NOT NULL de columnas antiguas para compatibilidad
    "ALTER TABLE floors ALTER COLUMN number DROP NOT NULL",
    "ALTER TABLE floors ALTER COLUMN letter DROP NOT NULL",
    // Eliminar restricción única antigua si existe
    "ALTER TABLE floors DROP CONSTRAINT IF EXISTS floors_portal_id_number_letter_key",
    "ALTER TABLE floors DROP CONSTRAINT IF EXISTS floors_portal_id_unit_label_key",
    // Rellenar unit_label con datos existentes
    "UPDATE floors SET unit_label = COALESCE(NULLIF(unit_label,''), number || 'º ' || letter) WHERE unit_label IS NULL OR unit_label = ''",
    // Push subscriptions
    "ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS floor_id TEXT",
    "ALTER TABLE push_subscriptions ALTER COLUMN floor_number DROP NOT NULL",
    "ALTER TABLE push_subscriptions ALTER COLUMN floor_letter DROP NOT NULL",
    "ALTER TABLE push_subscriptions DROP CONSTRAINT IF EXISTS push_subscriptions_portal_id_floor_number_floor_letter_key",
    // Call log
    "ALTER TABLE call_log ADD COLUMN IF NOT EXISTS floor_id TEXT",
    "ALTER TABLE call_log ADD COLUMN IF NOT EXISTS floor_label TEXT NOT NULL DEFAULT ''",
    // Notices table
    "CREATE TABLE IF NOT EXISTS notices (id TEXT PRIMARY KEY, portal_id TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'general', title TEXT NOT NULL, body TEXT NOT NULL, sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), recipients_count INTEGER NOT NULL DEFAULT 0)",
    // Portals: eliminar FK y NOT NULL de client_id para poder crear portales sin client_id
    "ALTER TABLE portals DROP CONSTRAINT IF EXISTS portals_client_id_fkey",
    "ALTER TABLE portals ALTER COLUMN client_id DROP NOT NULL",
    // Portals: añadir user_id si no existe
    "ALTER TABLE portals ADD COLUMN IF NOT EXISTS user_id INT",
  ];
  for (const sql of migrations) {
    await pool.query(sql).catch(e => log('Migration skip: ' + e.message));
  }

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

async function checkPortalOwner(portalId, clientId) {
  const r = await pool.query('SELECT id FROM portals WHERE id=$1 AND client_id=$2', [portalId, clientId]);
  return r.rows.length > 0;
}

// ── Express ───────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ══════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Faltan campos' });
    if (password.length < 8) return res.status(400).json({ error: 'Contraseña demasiado corta' });

    const existing = await pool.query('SELECT id FROM clients WHERE email=$1', [email]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email ya registrado' });

    const id   = uid();
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO clients (id,name,email,password) VALUES ($1,$2,$3,$4)', [id, name, email, hash]);

    const token = jwt.sign({ id, email, name }, JWT_SECRET, { expiresIn: '30d' });
    log(`Nuevo cliente: ${email}`);
    res.json({ token, client: { id, name, email } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Faltan campos' });

    const result = await pool.query('SELECT * FROM clients WHERE email=$1', [email]);
    const client = result.rows[0];
    if (!client) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

    const ok = await bcrypt.compare(password, client.password);
    if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    if (!client.active) return res.status(403).json({ error: 'Cuenta suspendida' });

    const token = jwt.sign({ id: client.id, email: client.email, name: client.name }, JWT_SECRET, { expiresIn: '30d' });
    log(`Login: ${email}`);
    res.json({ token, client: { id: client.id, name: client.name, email: client.email, plan: client.plan } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Falta el nombre' });
    await pool.query('UPDATE clients SET name=$1 WHERE id=$2', [name, req.client.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Faltan campos' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'La nueva contraseña es demasiado corta' });

    const result = await pool.query('SELECT password FROM clients WHERE id=$1', [req.client.id]);
    const ok = await bcrypt.compare(currentPassword, result.rows[0].password);
    if (!ok) return res.status(401).json({ error: 'La contraseña actual no es correcta' });

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE clients SET password=$1 WHERE id=$2', [hash, req.client.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// PORTALES
// ══════════════════════════════════════════════════════════

app.get('/api/portals', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*,
        COUNT(DISTINCT f.id) as floor_count,
        COUNT(DISTINCT ps.id) as active_neighbors
      FROM portals p
      LEFT JOIN floors f ON f.portal_id = p.id
      LEFT JOIN push_subscriptions ps ON ps.portal_id = p.id
      WHERE p.client_id = $1
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `, [req.client.id]);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/portals', authMiddleware, async (req, res) => {
  try {
    const { name, address, city } = req.body;
    if (!name || !address) return res.status(400).json({ error: 'Faltan nombre y dirección' });
    const id = uid();
    await pool.query('INSERT INTO portals (id,client_id,name,address,city) VALUES ($1,$2,$3,$4,$5)',
      [id, req.client.id, name, address, city || '']);
    log(`Portal creado: ${name}`);
    res.json({ id, name, address, city: city || '' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/portals/:id', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.id, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });
    const { name, address, city } = req.body;
    await pool.query('UPDATE portals SET name=COALESCE($1,name), address=COALESCE($2,address), city=COALESCE($3,city) WHERE id=$4',
      [name, address, city, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/portals/:id', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.id, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });
    await pool.query('DELETE FROM portals WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Datos públicos del portal (para el QR del visitante) ──
app.get('/api/portal/:portalId/public', async (req, res) => {
  try {
    const portal = await pool.query('SELECT * FROM portals WHERE id=$1 AND active=true', [req.params.portalId]);
    if (!portal.rows.length) return res.status(404).json({ error: 'Portal no encontrado' });

    const floors = await pool.query(`
      SELECT id, unit_label FROM floors
      WHERE portal_id=$1
      ORDER BY unit_label
    `, [req.params.portalId]);

    const p = portal.rows[0];
    res.json({
      id:      p.id,
      name:    p.name,
      address: p.address,
      city:    p.city,
      floors:  floors.rows.map(f => ({ id: f.id, label: f.unit_label }))
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// VIVIENDAS (unit_label libre)
// ══════════════════════════════════════════════════════════

app.get('/api/portals/:portalId/floors', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });

    const result = await pool.query(`
      SELECT f.*,
        CASE WHEN ps.id IS NOT NULL THEN true ELSE false END as has_push
      FROM floors f
      LEFT JOIN push_subscriptions ps ON ps.floor_id = f.id
      WHERE f.portal_id=$1
      ORDER BY f.unit_label
    `, [req.params.portalId]);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/portals/:portalId/floors', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });

    const { unit_label, resident_name } = req.body;
    if (!unit_label) return res.status(400).json({ error: 'Falta el identificador de la vivienda' });

    // Ver columnas actuales de la tabla
    const cols = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='floors'");
    log('Columnas floors: ' + cols.rows.map(r=>r.column_name).join(', '));

    const id = uid();
    await pool.query('INSERT INTO floors (id,portal_id,unit_label,resident_name) VALUES ($1,$2,$3,$4)',
      [id, req.params.portalId, unit_label.trim(), resident_name || '']);
    res.json({ id, unit_label, resident_name: resident_name || '' });
  } catch(e) {
    log('ERROR crear piso: ' + e.message + ' | code: ' + e.code);
    if (e.code === '23505') return res.status(409).json({ error: 'Esta vivienda ya existe en este portal' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/portals/:portalId/floors/:floorId', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });
    const { unit_label, resident_name } = req.body;
    await pool.query('UPDATE floors SET unit_label=COALESCE($1,unit_label), resident_name=COALESCE($2,resident_name) WHERE id=$3 AND portal_id=$4',
      [unit_label, resident_name, req.params.floorId, req.params.portalId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/portals/:portalId/floors/:floorId', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });
    await pool.query('DELETE FROM floors WHERE id=$1 AND portal_id=$2', [req.params.floorId, req.params.portalId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Resetear vecino de una vivienda (nuevo vecino)
app.post('/api/portals/:portalId/floors/:floorId/reset', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });
    await pool.query('DELETE FROM push_subscriptions WHERE floor_id=$1', [req.params.floorId]);
    log(`Vivienda reseteada: ${req.params.floorId}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// PUSH SUBSCRIPTIONS
// ══════════════════════════════════════════════════════════

app.post('/api/subscribe', async (req, res) => {
  try {
    const { portalId, floorId, subscription } = req.body;
    if (!portalId || !floorId || !subscription) return res.status(400).json({ error: 'Faltan datos' });

    const id = uid();
    await pool.query(`
      INSERT INTO push_subscriptions (id,portal_id,floor_id,subscription,updated_at)
      VALUES ($1,$2,$3,$4,NOW())
      ON CONFLICT (floor_id)
      DO UPDATE SET subscription=EXCLUDED.subscription, updated_at=NOW()
    `, [id, portalId, floorId, JSON.stringify(subscription)]);

    log(`Push registrado: portal=${portalId} floor=${floorId}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUB });
});

// ══════════════════════════════════════════════════════════
// AVISOS A VECINOS
// ══════════════════════════════════════════════════════════

app.post('/api/portals/:portalId/notify', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });

    const { type, title, body, recipients } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'Faltan título y mensaje' });

    // Obtener suscripciones según destinatarios
    let subsQuery = `
      SELECT ps.subscription, f.unit_label
      FROM push_subscriptions ps
      JOIN floors f ON f.id = ps.floor_id
      WHERE ps.portal_id=$1
    `;
    const subs = await pool.query(subsQuery, [req.params.portalId]);

    const noticeIcons = {
      urgent: '🚨', maintenance: '🔧', meeting: '📅',
      general: '📢', community: '🎉', water: '💧'
    };
    const icon = noticeIcons[type] || '📢';

    let sent = 0;
    for (const row of subs.rows) {
      try {
        await webPush.sendNotification(JSON.parse(row.subscription), JSON.stringify({
          title: `${icon} ${title}`,
          body,
          type: 'notice'
        }));
        sent++;
      } catch(err) {
        // Si la suscripción expiró, eliminarla
        if (err.statusCode === 410) {
          await pool.query('DELETE FROM push_subscriptions WHERE subscription=$1', [row.subscription]);
        }
      }
    }

    // Guardar en historial
    const noticeId = uid();
    await pool.query('INSERT INTO notices (id,portal_id,type,title,body,recipients_count) VALUES ($1,$2,$3,$4,$5,$6)',
      [noticeId, req.params.portalId, type || 'general', title, body, sent]);

    log(`Aviso enviado: "${title}" → ${sent} vecinos en portal ${req.params.portalId}`);
    res.json({ ok: true, sent });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/portals/:portalId/notices', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });

    const result = await pool.query(`
      SELECT * FROM notices WHERE portal_id=$1
      ORDER BY sent_at DESC LIMIT 50
    `, [req.params.portalId]);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// ESTADÍSTICAS
// ══════════════════════════════════════════════════════════

app.get('/api/portals/:portalId/stats', authMiddleware, async (req, res) => {
  try {
    if (!await checkPortalOwner(req.params.portalId, req.client.id))
      return res.status(404).json({ error: 'Portal no encontrado' });

    const stats = await pool.query(`
      SELECT
        COUNT(*) as total_calls,
        SUM(CASE WHEN answered THEN 1 ELSE 0 END) as answered_calls,
        ROUND(AVG(CASE WHEN answered AND duration_sec > 0 THEN duration_sec END)) as avg_duration_sec
      FROM call_log WHERE portal_id=$1
        AND started_at > NOW() - INTERVAL '30 days'
    `, [req.params.portalId]);

    const recent = await pool.query(`
      SELECT * FROM call_log WHERE portal_id=$1
      ORDER BY started_at DESC LIMIT 20
    `, [req.params.portalId]);

    res.json({ ...stats.rows[0], recent: recent.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// HTTP SERVER
// ══════════════════════════════════════════════════════════

const server = app.listen(PORT, async () => {
  await initDB();
  log(`Servidor listo en puerto ${PORT}`);
});

// ══════════════════════════════════════════════════════════
// WEBSOCKET — señalización WebRTC
// ══════════════════════════════════════════════════════════

const wss   = new WebSocket.Server({ server });
const rooms = new Map();

function getRoom(roomId) {
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

    const { type, room: roomId } = msg;

    // ── Join ──────────────────────────────────────────────
    if (type === 'join') {
      const { role, portalId, floorId, floorLabel } = msg;
      if (!roomId || !role) return;

      const room = getRoom(roomId);
      ws._room = roomId;
      ws._role = role;
      room[role] = ws;
      log(`${role} → sala ${roomId}`);

      if (role === 'visitor') {
        // Registrar llamada
        const callLogId = uid();
        room.callLogId  = callLogId;
        await pool.query(`
          INSERT INTO call_log (id,portal_id,floor_id,floor_label)
          VALUES ($1,$2,$3,$4)
        `, [callLogId, portalId || roomId.split('-')[0], floorId || null, floorLabel || roomId]);

        const neighborOnline = room.neighbor && room.neighbor.readyState === WebSocket.OPEN;

        if (neighborOnline) {
          safeSend(room.neighbor, { type: 'visitor-calling' });
          safeSend(ws, { type: 'notification-sent' });
          log(`Vecino online → sala ${roomId}`);
        } else {
          // Enviar push notification
          let sub = null;
          if (floorId) {
            const r = await pool.query('SELECT subscription FROM push_subscriptions WHERE floor_id=$1', [floorId]);
            if (r.rows.length) sub = r.rows[0].subscription;
          }

          if (sub && VAPID_PUB) {
            try {
              await webPush.sendNotification(JSON.parse(sub), JSON.stringify({
                title: '🔔 Alguien llama al portal',
                body:  'Hay una visita esperando. Pulsa para contestar.',
                url:   `https://danieletom007-gif.github.io/portero-virtual/vecino.html?portal=${portalId}&floor=${floorId}&contestar=true`,
                room:  roomId
              }));
              safeSend(ws, { type: 'notification-sent' });
              log(`Push enviado → sala ${roomId}`);
            } catch(err) {
              log(`Error push: ${err.message}`);
              if (err.statusCode === 410) {
                await pool.query('DELETE FROM push_subscriptions WHERE floor_id=$1', [floorId]);
              }
              safeSend(ws, { type: 'busy' });
            }
          } else {
            safeSend(ws, { type: 'busy' });
          }
        }
      }
    }

    // ── Señalización WebRTC ───────────────────────────────
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


    if (type === 'chat') {
      const room = rooms.get(roomId);
      if (!room) return;
      const target = ws._role === 'visitor' ? room.neighbor : room.visitor;
      safeSend(target, { type: 'chat', text: msg.text, from: msg.from });
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

// Ping para mantener conexiones vivas
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.ping();
  });
}, 30000);
