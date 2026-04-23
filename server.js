require('dotenv').config();
const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const webpush    = require('web-push');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');

// ─── App & DB ────────────────────────────────────────────────────────────────
const app  = express();
const server = http.createServer(app);
const wss  = new WebSocket.Server({ server });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(cors());
app.use(express.json());

// ─── VAPID ───────────────────────────────────────────────────────────────────
webpush.setVapidDetails(
  process.env.VAPID_EMAIL,
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// ─── JWT helper ──────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'portero-secret-fallback';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ─── DB init ─────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS portals (
      id TEXT PRIMARY KEY,
      user_id INT REFERENCES users(id),
      name TEXT NOT NULL,
      address TEXT,
      city TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS floors (
      id TEXT PRIMARY KEY,
      portal_id TEXT REFERENCES portals(id) ON DELETE CASCADE,
      unit_label TEXT NOT NULL,
      number INT,
      letter TEXT,
      push_subscription JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS call_log (
      id SERIAL PRIMARY KEY,
      portal_id TEXT REFERENCES portals(id) ON DELETE CASCADE,
      floor_id TEXT,
      floor_label TEXT,
      started_at TIMESTAMPTZ DEFAULT NOW(),
      answered BOOLEAN DEFAULT FALSE,
      duration_seconds INT
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notices (
      id SERIAL PRIMARY KEY,
      portal_id TEXT REFERENCES portals(id) ON DELETE CASCADE,
      user_id INT REFERENCES users(id),
      type TEXT,
      title TEXT,
      body TEXT,
      sent_at TIMESTAMPTZ DEFAULT NOW(),
      recipients INT DEFAULT 0
    )
  `);
  // Migración segura: quitar NOT NULL de columns legacy si existen
  await pool.query(`ALTER TABLE floors ALTER COLUMN number DROP NOT NULL`).catch(()=>{});
  await pool.query(`ALTER TABLE floors ALTER COLUMN letter DROP NOT NULL`).catch(()=>{});
  console.log('✅ DB lista');
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function genId(len = 16) {
  const chars = 'abcdef0123456789';
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ─── AUTH ────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (email, password_hash, name) VALUES ($1,$2,$3) RETURNING id, email, name',
      [email.toLowerCase().trim(), hash, name || '']
    );
    const user = r.rows[0];
    res.json({ token: signToken({ id: user.id, email: user.email }), user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email ya registrado' });
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });
    res.json({
      token: signToken({ id: user.id, email: user.email }),
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const { name } = req.body;
  try {
    await pool.query('UPDATE users SET name = $1 WHERE id = $2', [name, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    const r = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    const user = r.rows[0];
    const ok = await bcrypt.compare(currentPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── PORTALES ────────────────────────────────────────────────────────────────
app.get('/api/portals', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM portals WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/portals', authMiddleware, async (req, res) => {
  const { name, address, city } = req.body;
  if (!name) return res.status(400).json({ error: 'name requerido' });
  try {
    const id = genId(16);
    const r = await pool.query(
      'INSERT INTO portals (id, user_id, name, address, city) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [id, req.user.id, name, address || '', city || '']
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/portals/:id', authMiddleware, async (req, res) => {
  const { name, address, city } = req.body;
  try {
    const r = await pool.query(
      'UPDATE portals SET name=$1, address=$2, city=$3 WHERE id=$4 AND user_id=$5 RETURNING *',
      [name, address || '', city || '', req.params.id, req.user.id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/portals/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM portals WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── PORTAL PÚBLICO (para visitante.html y vecino.html sin auth) ─────────────
app.get('/api/portal/:portalId/public', async (req, res) => {
  try {
    const pr = await pool.query('SELECT id, name, address, city FROM portals WHERE id = $1', [req.params.portalId]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });
    const portal = pr.rows[0];

    const fr = await pool.query(
      'SELECT id, unit_label, number, letter FROM floors WHERE portal_id = $1 ORDER BY unit_label ASC',
      [req.params.portalId]
    );
    // Devuelve floors con { id, label } para el selector del visitante
    portal.floors = fr.rows.map(f => ({
      id:    f.id,
      label: f.unit_label || `${f.number || ''}${f.letter || ''}`
    }));
    res.json(portal);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── VIVIENDAS ────────────────────────────────────────────────────────────────
app.get('/api/portals/:id/floors', authMiddleware, async (req, res) => {
  try {
    // Verificar que el portal pertenece al usuario
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    const r = await pool.query(
      `SELECT id, unit_label, number, letter,
              push_subscription IS NOT NULL AS installed,
              created_at
       FROM floors WHERE portal_id = $1 ORDER BY unit_label ASC`,
      [req.params.id]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/portals/:id/floors', authMiddleware, async (req, res) => {
  const { unit_label, number, letter } = req.body;
  if (!unit_label) return res.status(400).json({ error: 'unit_label requerido' });
  try {
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    const floorId = genId(16);
    const r = await pool.query(
      'INSERT INTO floors (id, portal_id, unit_label, number, letter) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [floorId, req.params.id, unit_label, number || null, letter || null]
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/portals/:portalId/floors/:floorId', authMiddleware, async (req, res) => {
  const { unit_label } = req.body;
  try {
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.portalId, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    const r = await pool.query(
      'UPDATE floors SET unit_label=$1 WHERE id=$2 AND portal_id=$3 RETURNING *',
      [unit_label, req.params.floorId, req.params.portalId]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Vivienda no encontrada' });
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/portals/:portalId/floors/:floorId', authMiddleware, async (req, res) => {
  try {
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.portalId, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    await pool.query('DELETE FROM floors WHERE id=$1 AND portal_id=$2', [req.params.floorId, req.params.portalId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/portals/:portalId/floors/:floorId/reset', authMiddleware, async (req, res) => {
  try {
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.portalId, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    await pool.query(
      'UPDATE floors SET push_subscription = NULL WHERE id=$1 AND portal_id=$2',
      [req.params.floorId, req.params.portalId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── VAPID PUBLIC KEY ─────────────────────────────────────────────────────────
app.get('/api/vapid-public-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

// ─── SUBSCRIBE ────────────────────────────────────────────────────────────────
// ✅ Acepta floorId (sistema nuevo) con fallback a floorNumber/floorLetter (legacy)
app.post('/api/subscribe', async (req, res) => {
  const { portalId, floorId, floorNumber, floorLetter, subscription } = req.body;

  if (!portalId || !subscription) {
    return res.status(400).json({ error: 'portalId y subscription son obligatorios' });
  }

  try {
    let floor;

    if (floorId) {
      // ✅ Sistema nuevo: busca por ID directo
      const r = await pool.query(
        'SELECT id FROM floors WHERE id = $1 AND portal_id = $2',
        [floorId, portalId]
      );
      floor = r.rows[0];
    }

    // Fallback legacy: buscar por número y letra si no encontró por floorId
    if (!floor && floorNumber !== undefined && floorNumber !== null && floorNumber !== '') {
      const r = await pool.query(
        `SELECT id FROM floors
         WHERE portal_id = $1 AND number = $2
           AND (letter = $3 OR letter IS NULL OR letter = '')`,
        [portalId, floorNumber, floorLetter || '']
      );
      floor = r.rows[0];
    }

    if (!floor) {
      return res.status(404).json({
        error: 'Vivienda no encontrada',
        debug: { floorId, floorNumber, floorLetter, portalId }
      });
    }

    await pool.query(
      'UPDATE floors SET push_subscription = $1 WHERE id = $2',
      [JSON.stringify(subscription), floor.id]
    );

    console.log(`✅ Push registrado — floor ${floor.id} (portal ${portalId})`);
    res.json({ ok: true, floorId: floor.id });

  } catch (e) {
    console.error('subscribe error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── AVISOS PUSH ──────────────────────────────────────────────────────────────
app.post('/api/portals/:id/notify', authMiddleware, async (req, res) => {
  const { title, body, type, floorIds } = req.body;
  try {
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    let query = 'SELECT id, push_subscription FROM floors WHERE portal_id = $1 AND push_subscription IS NOT NULL';
    const params = [req.params.id];

    // Si se especifican pisos concretos, filtrar
    if (floorIds && floorIds.length > 0) {
      query += ` AND id = ANY($2::text[])`;
      params.push(floorIds);
    }

    const r = await pool.query(query, params);
    const floors = r.rows;

    let sent = 0;
    const payload = JSON.stringify({ title: title || 'Aviso del portal', body: body || '', type: type || 'info' });

    for (const floor of floors) {
      try {
        const sub = typeof floor.push_subscription === 'string'
          ? JSON.parse(floor.push_subscription)
          : floor.push_subscription;
        await webpush.sendNotification(sub, payload);
        sent++;
      } catch (e) {
        console.warn(`Push failed floor ${floor.id}:`, e.statusCode || e.message);
        // Si la suscripción es inválida (410), limpiarla
        if (e.statusCode === 410) {
          await pool.query('UPDATE floors SET push_subscription = NULL WHERE id = $1', [floor.id]);
        }
      }
    }

    // Guardar en historial
    await pool.query(
      'INSERT INTO notices (portal_id, user_id, type, title, body, recipients) VALUES ($1,$2,$3,$4,$5,$6)',
      [req.params.id, req.user.id, type || 'info', title, body, sent]
    );

    res.json({ ok: true, sent, total: floors.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/portals/:id/notices', authMiddleware, async (req, res) => {
  try {
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    const r = await pool.query(
      'SELECT * FROM notices WHERE portal_id=$1 ORDER BY sent_at DESC LIMIT 50',
      [req.params.id]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── ESTADÍSTICAS ─────────────────────────────────────────────────────────────
app.get('/api/portals/:id/stats', authMiddleware, async (req, res) => {
  try {
    const pr = await pool.query('SELECT id FROM portals WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!pr.rows[0]) return res.status(404).json({ error: 'Portal no encontrado' });

    const [totalFloors, installedFloors, totalCalls, recentCalls] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM floors WHERE portal_id=$1', [req.params.id]),
      pool.query('SELECT COUNT(*) FROM floors WHERE portal_id=$1 AND push_subscription IS NOT NULL', [req.params.id]),
      pool.query('SELECT COUNT(*) FROM call_log WHERE portal_id=$1', [req.params.id]),
      pool.query(
        `SELECT cl.*, f.unit_label as floor_label
         FROM call_log cl
         LEFT JOIN floors f ON f.id = cl.floor_id
         WHERE cl.portal_id=$1
         ORDER BY cl.started_at DESC LIMIT 20`,
        [req.params.id]
      )
    ]);

    res.json({
      totalFloors:     parseInt(totalFloors.rows[0].count),
      installedFloors: parseInt(installedFloors.rows[0].count),
      totalCalls:      parseInt(totalCalls.rows[0].count),
      recentCalls:     recentCalls.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── WEBSOCKET ───────────────────────────────────────────────────────────────
// rooms: Map<roomId, Set<WebSocket>>
const rooms = new Map();

function getRoomClients(room) {
  if (!rooms.has(room)) rooms.set(room, new Set());
  return rooms.get(room);
}

function broadcast(room, data, exclude = null) {
  const clients = getRoomClients(room);
  const msg = JSON.stringify(data);
  for (const ws of clients) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  }
}

wss.on('connection', (ws) => {
  ws.room     = null;
  ws.role     = null;
  ws.portalId = null;
  ws.floorId  = null;

  ws.on('message', async (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    switch (data.type) {

      case 'join': {
        const { room, role, portalId, floorId, floorLabel } = data;
        if (!room) return;

        // Salir de sala anterior si tenía
        if (ws.room) {
          const prev = getRoomClients(ws.room);
          prev.delete(ws);
          if (prev.size === 0) rooms.delete(ws.room);
        }

        ws.room     = room;
        ws.role     = role;
        ws.portalId = portalId;
        ws.floorId  = floorId;
        ws.floorLabel = floorLabel;

        getRoomClients(room).add(ws);
        console.log(`[WS] join → room:${room} role:${role} floor:${floorId}`);

        // Notificar al vecino que un visitante está llamando
        if (role === 'visitor') {
          broadcast(room, {
            type: 'visitor-calling',
            portalId,
            floorId,
            floorLabel,
            room
          }, ws);

          // Registrar llamada en la BD
          try {
            await pool.query(
              'INSERT INTO call_log (portal_id, floor_id, floor_label) VALUES ($1,$2,$3)',
              [portalId, floorId, floorLabel || '']
            );
          } catch (e) {
            console.warn('call_log insert error:', e.message);
          }

          // Enviar push al vecino si tiene suscripción
          if (portalId && floorId) {
            try {
              const fr = await pool.query(
                'SELECT push_subscription, unit_label FROM floors WHERE id=$1 AND portal_id=$2',
                [floorId, portalId]
              );
              const floor = fr.rows[0];
              if (floor && floor.push_subscription) {
                const sub = typeof floor.push_subscription === 'string'
                  ? JSON.parse(floor.push_subscription)
                  : floor.push_subscription;

                const label = floorLabel || floor.unit_label || '';
                const vecUrl = `https://danieletom007-gif.github.io/portero-virtual/vecino.html?portal=${portalId}&floor=${floorId}&contestar=true`;

                await webpush.sendNotification(sub, JSON.stringify({
                  title: '🔔 Visita en el portal',
                  body:  `Alguien llama a ${label}`,
                  url:   vecUrl,
                  portalId,
                  floorId,
                  room
                })).catch(async (e) => {
                  console.warn('push send error:', e.statusCode);
                  if (e.statusCode === 410) {
                    await pool.query('UPDATE floors SET push_subscription = NULL WHERE id=$1', [floorId]);
                  }
                });
              }
            } catch (e) {
              console.warn('push lookup error:', e.message);
            }
          }
        }

        if (role === 'neighbor') {
          // Avisar al visitante que el vecino está listo (si ya estaba esperando)
          broadcast(room, { type: 'neighbor-ready', room }, ws);
        }
        break;
      }

      case 'neighbor-ready':
      case 'offer':
      case 'answer':
      case 'ice':
      case 'busy':
      case 'hangup': {
        broadcast(ws.room, data, ws);
        break;
      }

      case 'chat': {
        // Reenviar mensaje de chat al otro lado de la llamada
        broadcast(ws.room, {
          type:    'chat',
          message: data.message,
          from:    ws.role
        }, ws);
        break;
      }

      default:
        console.warn('[WS] tipo desconocido:', data.type);
    }
  });

  ws.on('close', () => {
    if (ws.room) {
      const clients = getRoomClients(ws.room);
      clients.delete(ws);
      // Avisar al otro lado que se desconectó
      broadcast(ws.room, { type: 'hangup', reason: 'disconnect' });
      if (clients.size === 0) rooms.delete(ws.room);
      console.log(`[WS] close → room:${ws.room} role:${ws.role}`);
    }
  });

  ws.on('error', (e) => console.error('[WS] error:', e.message));
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', version: '2.1', time: new Date().toISOString() }));
app.get('/health', (req, res) => res.json({ ok: true }));

// ─── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  server.listen(PORT, () => console.log(`🚀 Portero Virtual en puerto ${PORT}`));
}).catch(e => {
  console.error('DB init error:', e);
  process.exit(1);
});
