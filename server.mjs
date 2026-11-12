import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual, createHash } from 'node:crypto';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1');
const PUBLIC_ORIGIN = new URL(process.env.PUBLIC_ORIGIN || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).origin;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD_SALT = process.env.ADMIN_PASSWORD_SALT || '';
const ADMIN_SALT = decodeSecret(ADMIN_PASSWORD_SALT);
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || (process.env.ADMIN_PASSWORD && ADMIN_SALT.length >= 16 ? scryptSync(process.env.ADMIN_PASSWORD, ADMIN_SALT, 64).toString('hex') : '');
const DATA_KEY = decodeSecret(process.env.DATA_ENCRYPTION_KEY);
const INDEX_KEY = decodeSecret(process.env.LOOKUP_HMAC_KEY);
const PROD = process.env.NODE_ENV === 'production';
const FIREBASE_AUTH_ENABLED = process.env.AUTH_PROVIDER === 'firebase';
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || '';
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || '';
const TERMS_VERSION = '2026-11-12-draft-1';
const PRIVACY_VERSION = '2026-11-12-draft-1';
const SAFETY_VERSION = '2026-11-12-draft-1';
const USER_COOKIE = 'ff_user';
const ADMIN_COOKIE = 'ff_admin';
const USER_SESSION_SECONDS = 60 * 60 * 24 * 7;
const ADMIN_SESSION_SECONDS = 60 * 60 * 4;

function decodeSecret(value) { const input = String(value || ''); return /^(?:[0-9a-f]{32}|[0-9a-f]{64})$/i.test(input) ? Buffer.from(input, 'hex') : Buffer.from(input, 'base64'); }

const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
if (nodeMajor < 22 || (nodeMajor === 22 && nodeMinor < 5)) throw new Error('Use Node.js 22.5 or newer.');
if (DATA_KEY.length !== 32 || INDEX_KEY.length !== 32) throw new Error('Missing keys. Run setup.ps1 first.');
if (!ADMIN_USERNAME || ADMIN_SALT.length < 16 || !/^[0-9a-f]{128}$/i.test(ADMIN_PASSWORD_HASH)) throw new Error('Missing developer login settings. Run setup.ps1 first.');
if (PROD && !PUBLIC_ORIGIN.startsWith('https://')) throw new Error('Production requires PUBLIC_ORIGIN=https://…');
if (FIREBASE_AUTH_ENABLED && (!FIREBASE_PROJECT_ID || !FIREBASE_API_KEY)) throw new Error('Firebase auth requires FIREBASE_PROJECT_ID and FIREBASE_API_KEY.');

const dataDir = resolve(process.env.DATA_DIR || resolve(ROOT, 'data'));
await mkdir(dataDir, { recursive: true });
const db = new DatabaseSync(resolve(dataDir, 'flight-friend.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, payload TEXT NOT NULL, email_idx TEXT NOT NULL UNIQUE, phone_idx TEXT NOT NULL UNIQUE, firebase_uid TEXT UNIQUE,
  password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
  traveler_visible INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf_hash TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feedback (id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS consent_events (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, admin_user TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS user_sessions_expiry ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS feedback_created ON feedback(created_at);
`);
if (!db.prepare('PRAGMA table_info(users)').all().some(column => column.name === 'firebase_uid')) db.exec('ALTER TABLE users ADD COLUMN firebase_uid TEXT');
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_firebase_uid ON users(firebase_uid) WHERE firebase_uid IS NOT NULL');
const airports = new Map(JSON.parse(await readFile(resolve(ROOT, 'airports.json'), 'utf8')).map(a => [a.code, a]));

const now = () => new Date().toISOString();
const sha256 = value => createHash('sha256').update(value).digest('hex');
const hmac = value => createHmac('sha256', INDEX_KEY).update(value).digest('hex');
function encrypt(value) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', DATA_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return [iv.toString('base64'), cipher.getAuthTag().toString('base64'), ciphertext.toString('base64')].join('.');
}
function decrypt(value) {
  const [iv, tag, ciphertext] = value.split('.');
  const decipher = createDecipheriv('aes-256-gcm', DATA_KEY, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]).toString('utf8'));
}
async function verifyFirebaseIdToken(idToken) {
  if (!FIREBASE_AUTH_ENABLED) throw Object.assign(new Error('Firebase authentication is not configured.'), { status: 503 });
  if (typeof idToken !== 'string' || idToken.length < 100 || idToken.length > 6000) throw Object.assign(new Error('Sign in again to continue.'), { status: 401 });
  let claims; try { claims = JSON.parse(Buffer.from(idToken.split('.')[1] || '', 'base64url').toString('utf8')); } catch { throw Object.assign(new Error('Sign in again to continue.'), { status: 401 }); }
  if (claims.aud !== FIREBASE_PROJECT_ID || claims.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}` || !claims.sub || Number(claims.exp) <= Math.floor(Date.now() / 1000)) throw Object.assign(new Error('Your sign-in token is not valid for this Flight Friend project.'), { status: 401 });
  const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(FIREBASE_API_KEY)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken }) });
  const result = await response.json().catch(() => ({}));
  const user = result.users?.[0];
  if (!response.ok || !user?.localId || user.disabled) throw Object.assign(new Error('Your verification expired. Please sign in again.'), { status: 401 });
  return user;
}
function firebaseBearer(req) { const value = req.headers.authorization || ''; return value.startsWith('Bearer ') ? value.slice(7) : ''; }
function safeText(value, max) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function normalizeEmail(value) { return safeText(value, 254).toLowerCase(); }
function normalizePhone(value) { return safeText(value, 25).replace(/[\s().-]/g, ''); }
function passwordHash(password, salt) { return scryptSync(password, decodeSecret(salt), 64).toString('hex'); }
function safeHashEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || !/^(?:[0-9a-f]{64}|[0-9a-f]{128})$/.test(a) || !/^(?:[0-9a-f]{64}|[0-9a-f]{128})$/.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
function json(res, status, data, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra });
  res.end(JSON.stringify(data));
}
function text(res, status, content, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(content);
}
function cookieValue(req, name) {
  const entry = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : '';
}
function cookie(res, name, value, seconds) {
  const secure = PROD ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${seconds}${secure}`);
}
function clearCookie(res, name) {
  const secure = PROD ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}
async function readBody(req, limit = 32_000) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > limit) throw Object.assign(new Error('Request is too large.'), { status: 413 }); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw Object.assign(new Error('Invalid request.'), { status: 400 }); }
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin || new URL(origin).origin !== PUBLIC_ORIGIN) throw Object.assign(new Error('Request origin was rejected.'), { status: 403 });
}
const rateBuckets = new Map();
function rateLimit(req, key, max, windowMs) {
  const ip = req.socket.remoteAddress || 'unknown', id = `${key}:${ip}`, time = Date.now();
  const bucket = rateBuckets.get(id) || { count: 0, start: time };
  if (time - bucket.start > windowMs) { bucket.count = 0; bucket.start = time; }
  bucket.count++; rateBuckets.set(id, bucket);
  if (rateBuckets.size > 5000) for (const [k, v] of rateBuckets) if (time - v.start > 3_600_000) rateBuckets.delete(k);
  if (bucket.count > max) throw Object.assign(new Error('Too many attempts. Please wait and try again.'), { status: 429 });
}
function userSession(req) {
  const token = cookieValue(req, USER_COOKIE); if (!token) return null;
  const session = db.prepare('SELECT s.user_id,u.status,u.firebase_uid FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(sha256(token), now()) || null;
  if (FIREBASE_AUTH_ENABLED && !session?.firebase_uid) return null;
  return session;
}
function adminSession(req, csrfRequired = false) {
  const token = cookieValue(req, ADMIN_COOKIE); if (!token) return null;
  const session = db.prepare('SELECT token_hash,username,csrf_hash,expires_at FROM admin_sessions WHERE token_hash=? AND expires_at>?').get(sha256(token), now());
  if (!session) return null;
  if (csrfRequired) {
    const sent = req.headers['x-csrf-token'] || '';
    if (!sent || !safeHashEqual(sha256(sent), session.csrf_hash)) throw Object.assign(new Error('Session check failed. Refresh the dashboard and try again.'), { status: 403 });
  }
  return session;
}
function userRecord(id) {
  const row = db.prepare('SELECT id,payload,status,traveler_visible,created_at FROM users WHERE id=?').get(id);
  return row ? { ...row, data: decrypt(row.payload) } : null;
}
function audit(username, action, target) {
  db.prepare('INSERT INTO audit_log (id,admin_user,action,target_id,created_at) VALUES (?,?,?,?,?)').run(randomUUID(), username, action, target, now());
}
function publicTravelers() {
  const rows = db.prepare("SELECT id,payload FROM users WHERE status='active' AND traveler_visible=1 ORDER BY created_at DESC").all();
  return rows.flatMap(row => {
    try {
      const data = decrypt(row.payload); if (!data.traveler) return [];
      const from = airports.get(data.traveler.from), to = airports.get(data.traveler.to); if (!from || !to) return [];
      return [{ id: row.id, name: data.name, from: from.code, to: to.code, delivered: 0, orders: 0, rating: 'New', score: 'New' }];
    } catch { return []; }
  });
}
function adminData() {
  const users = db.prepare('SELECT id,payload,status,traveler_visible,created_at FROM users ORDER BY created_at DESC').all().map(row => {
    const d = decrypt(row.payload); const from = d.traveler && airports.get(d.traveler.from); const to = d.traveler && airports.get(d.traveler.to);
    return { id: row.id, name: d.name, email: d.email, phone: d.phone, createdAt: row.created_at, status: row.status, travelerVisible: !!row.traveler_visible, from: from?.city || '', to: to?.city || '', flightNumber: d.traveler?.flightNumber || '', travelDate: d.traveler?.travelDate || '', consents: d.consents || {} };
  });
  const feedbackRows = db.prepare('SELECT id,payload,status,created_at FROM feedback ORDER BY created_at DESC').all().map(row => ({ id: row.id, ...decrypt(row.payload), status: row.status, createdAt: row.created_at }));
  const visitorConsents = db.prepare('SELECT id,payload,created_at FROM consent_events ORDER BY created_at DESC LIMIT 250').all().map(row => ({ id: row.id, ...decrypt(row.payload), createdAt: row.created_at }));
  const consentCount = db.prepare('SELECT count(*) AS n FROM consent_events').get().n;
  return { users, feedback: feedbackRows, visitorConsents, consents: consentCount, audits: db.prepare('SELECT action,target_id AS target,created_at AS createdAt FROM audit_log ORDER BY created_at DESC LIMIT 30').all(), stats: { users: users.length, listed: users.filter(u => u.status === 'active' && u.travelerVisible).length, feedback: feedbackRows.filter(f => f.status === 'new').length, consents: consentCount } };
}
async function handle(req, res) {
  const url = new URL(req.url, PUBLIC_ORIGIN);
  const path = url.pathname;
  if (req.method === 'GET' && path === '/') return text(res, 200, await readFile(resolve(ROOT, 'public/index.html'), 'utf8'), 'text/html; charset=utf-8');
  if (req.method === 'GET' && (path === '/admin' || path === '/admin/')) return text(res, 200, await readFile(resolve(ROOT, 'public/admin.html'), 'utf8'), 'text/html; charset=utf-8');
  if (req.method === 'GET' && path === '/firebase-auth.js') return text(res, 200, await readFile(resolve(ROOT, 'public/firebase-auth.js'), 'utf8'), 'text/javascript; charset=utf-8');
  if (req.method === 'GET' && path === '/favicon.ico') { res.writeHead(204); return res.end(); }
  if (req.method === 'GET' && path === '/api/health') return json(res, 200, { ok: true, app: 'Flight Friend' });
  if (req.method === 'GET' && path === '/api/travelers') return json(res, 200, { travelers: publicTravelers() });
  if (req.method === 'GET' && path === '/api/me') {
    const session = userSession(req); if (!session || session.status !== 'active') return json(res, 200, { user: null });
    const row = userRecord(session.user_id); return json(res, 200, { user: row ? { id: row.id, name: row.data.name } : null });
  }
  if (req.method !== 'GET' && path.startsWith('/api/')) sameOrigin(req);
  if (req.method === 'POST' && path === '/api/visitor-consent') {
    rateLimit(req, 'visitor-consent', 50, 60_000); const body = await readBody(req);
    if (body.ageConfirmed !== true || body.termsConfirmed !== true || body.privacyConfirmed !== true) return json(res, 400, { error: 'Please accept the age, terms, and privacy statements.' });
    db.prepare('INSERT INTO consent_events (id,payload,created_at) VALUES (?,?,?)').run(randomUUID(), encrypt({ ageConfirmed: true, termsVersion: TERMS_VERSION, privacyVersion: PRIVACY_VERSION }), now());
    return json(res, 201, { ok: true });
  }
  if (req.method === 'POST' && path === '/api/firebase/register') {
    rateLimit(req, 'firebase-register', 8, 60 * 60_000); const b = await readBody(req); const firebaseUser = await verifyFirebaseIdToken(firebaseBearer(req));
    const name = safeText(b.name, 100), email = normalizeEmail(firebaseUser.email || ''), phone = normalizePhone(firebaseUser.phoneNumber || '');
    if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{8,15}$/.test(phone)) return json(res, 400, { error: 'Verify a valid email address and phone number before continuing.' });
    if (b.ageConfirmed !== true || b.termsConfirmed !== true || b.privacyConfirmed !== true || b.safetyConfirmed !== true) return json(res, 400, { error: 'Confirm the age, terms, privacy, and safety statements to continue.' });
    let traveler = null;
    if (b.traveler !== null && b.traveler !== undefined) { const from = safeText(b.traveler.from, 8), to = safeText(b.traveler.to, 8); if (!airports.has(from) || !airports.has(to) || from === to) return json(res, 400, { error: 'Choose two different airports from the list.' }); const date = safeText(b.traveler.travelDate, 10), flightNumber = safeText(b.traveler.flightNumber, 15).replace(/[^a-zA-Z0-9 -]/g, ''); if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return json(res, 400, { error: 'Enter a valid travel date.' }); traveler = { from, to, travelDate: date, flightNumber }; }
    const uid = firebaseUser.localId, emailIdx = hmac('email:' + email), phoneIdx = hmac('phone:' + phone), existing = db.prepare('SELECT id FROM users WHERE firebase_uid=?').get(uid);
    if (!existing && db.prepare('SELECT 1 FROM users WHERE email_idx=? OR phone_idx=?').get(emailIdx, phoneIdx)) return json(res, 409, { error: 'An account with that email or phone already exists. Sign in to the existing account.' });
    const id = existing?.id || randomUUID(), createdAt = now(), payload = { name, email, phone: firebaseUser.phoneNumber, traveler, consents: { ageConfirmedAt: createdAt, termsVersion: TERMS_VERSION, privacyVersion: PRIVACY_VERSION, safetyVersion: SAFETY_VERSION } };
    if (existing) db.prepare('UPDATE users SET payload=?,traveler_visible=? WHERE id=?').run(encrypt(payload), traveler ? 1 : 0, id);
    else { const salt = randomBytes(16).toString('hex'), randomPasswordHash = passwordHash(randomBytes(48).toString('base64url'), salt); db.prepare("INSERT INTO users (id,payload,email_idx,phone_idx,firebase_uid,password_salt,password_hash,status,traveler_visible,created_at) VALUES (?,?,?,?,?,?,?,'pending',?,?)").run(id, encrypt(payload), emailIdx, phoneIdx, uid, salt, randomPasswordHash, traveler ? 1 : 0, createdAt); }
    return json(res, 201, { ok: true, pendingEmailVerification: !firebaseUser.emailVerified });
  }
  if (req.method === 'POST' && path === '/api/firebase/session') {
    rateLimit(req, 'firebase-session', 12, 15 * 60_000); const firebaseUser = await verifyFirebaseIdToken(firebaseBearer(req));
    if (!firebaseUser.emailVerified || !firebaseUser.phoneNumber) return json(res, 403, { error: !firebaseUser.emailVerified ? 'Verify your email from the link we sent before logging in.' : 'Verify your phone number by SMS before logging in.' });
    const row = db.prepare('SELECT id,status FROM users WHERE firebase_uid=?').get(firebaseUser.localId); if (!row) return json(res, 404, { error: 'Finish sign-up before logging in.' }); if (row.status === 'suspended') return json(res, 403, { error: 'This account is currently suspended.' });
    db.prepare('UPDATE users SET status=\'active\' WHERE id=?').run(row.id); const token = randomBytes(32).toString('base64url'), expires = new Date(Date.now() + USER_SESSION_SECONDS * 1000).toISOString(); db.prepare('INSERT INTO user_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').run(sha256(token), row.id, expires); cookie(res, USER_COOKIE, token, USER_SESSION_SECONDS); return json(res, 200, { ok: true });
  }
  if (req.method === 'POST' && path === '/api/register') {
    if (FIREBASE_AUTH_ENABLED) return json(res, 410, { error: 'Use email verification and phone SMS sign-in.' });
    rateLimit(req, 'register', 8, 60 * 60_000); const b = await readBody(req);
    if (Object.hasOwn(b, 'aadhaar') || Object.hasOwn(b, 'aadhaarNumber')) return json(res, 400, { error: 'Aadhaar numbers are not collected by this prototype.' });
    const name = safeText(b.name, 100), email = normalizeEmail(b.email), phone = normalizePhone(b.phone), password = typeof b.password === 'string' ? b.password : '';
    if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\+?\d{8,15}$/.test(phone)) return json(res, 400, { error: 'Enter a valid name, email, and phone number.' });
    if (password.length < 12 || password.length > 128) return json(res, 400, { error: 'Choose a password between 12 and 128 characters.' });
    if (b.ageConfirmed !== true || b.termsConfirmed !== true || b.privacyConfirmed !== true || b.safetyConfirmed !== true) return json(res, 400, { error: 'Confirm the age, terms, privacy, and safety statements to continue.' });
    let traveler = null;
    if (b.traveler !== null && b.traveler !== undefined) {
      const from = safeText(b.traveler.from, 8), to = safeText(b.traveler.to, 8);
      if (!airports.has(from) || !airports.has(to) || from === to) return json(res, 400, { error: 'Choose two different airports from the list.' });
      const date = safeText(b.traveler.travelDate, 10), flightNumber = safeText(b.traveler.flightNumber, 15).replace(/[^a-zA-Z0-9 -]/g, '');
      if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return json(res, 400, { error: 'Enter a valid travel date.' });
      traveler = { from, to, travelDate: date, flightNumber };
    }
    const emailIdx = hmac(`email:${email}`), phoneIdx = hmac(`phone:${phone}`);
    if (db.prepare('SELECT 1 FROM users WHERE email_idx=? OR phone_idx=?').get(emailIdx, phoneIdx)) return json(res, 409, { error: 'An account with that email or phone already exists.' });
    const id = randomUUID(), createdAt = now(), salt = randomBytes(16).toString('hex');
    const payload = { name, email, phone, traveler, consents: { ageConfirmedAt: createdAt, termsVersion: TERMS_VERSION, privacyVersion: PRIVACY_VERSION, safetyVersion: SAFETY_VERSION } };
    try { db.prepare('INSERT INTO users (id,payload,email_idx,phone_idx,password_salt,password_hash,status,traveler_visible,created_at) VALUES (?,?,?,?,?,? ,\'active\',?,?)').run(id, encrypt(payload), emailIdx, phoneIdx, salt, passwordHash(password, salt), traveler ? 1 : 0, createdAt); }
    catch { return json(res, 409, { error: 'An account with that email or phone already exists.' }); }
    const token = randomBytes(32).toString('base64url'), expires = new Date(Date.now() + USER_SESSION_SECONDS * 1000).toISOString();
    db.prepare('INSERT INTO user_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').run(sha256(token), id, expires); cookie(res, USER_COOKIE, token, USER_SESSION_SECONDS);
    return json(res, 201, { ok: true, user: { id, name } });
  }
  if (req.method === 'POST' && path === '/api/login') {
    if (FIREBASE_AUTH_ENABLED) return json(res, 410, { error: 'Use email verification and phone SMS sign-in.' });
    rateLimit(req, 'user-login', 12, 15 * 60_000); const b = await readBody(req); const contact = safeText(b.contact, 254).toLowerCase(), password = typeof b.password === 'string' ? b.password : '';
    const phone = normalizePhone(contact); const keys = [hmac(`email:${contact}`), hmac(`phone:${phone}`)];
    const row = db.prepare('SELECT id,password_salt,password_hash,status FROM users WHERE email_idx=? OR phone_idx=?').get(...keys);
    if (!row || row.status !== 'active' || !safeHashEqual(passwordHash(password, row.password_salt), row.password_hash)) return json(res, 401, { error: 'Email/phone or password is incorrect.' });
    const token = randomBytes(32).toString('base64url'), expires = new Date(Date.now() + USER_SESSION_SECONDS * 1000).toISOString();
    db.prepare('INSERT INTO user_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').run(sha256(token), row.id, expires); cookie(res, USER_COOKIE, token, USER_SESSION_SECONDS);
    return json(res, 200, { ok: true });
  }
  if (req.method === 'POST' && path === '/api/logout') {
    const token = cookieValue(req, USER_COOKIE); if (token) db.prepare('DELETE FROM user_sessions WHERE token_hash=?').run(sha256(token)); clearCookie(res, USER_COOKIE); return json(res, 200, { ok: true });
  }
  if (req.method === 'POST' && path === '/api/feedback') {
    rateLimit(req, 'feedback', 10, 60 * 60_000); const b = await readBody(req); const topic = safeText(b.topic, 60), message = safeText(b.message, 1200);
    if (!['Something confusing','A feature idea','Something I loved','Safety or accessibility','Other'].includes(topic) || message.length < 3) return json(res, 400, { error: 'Choose a topic and write at least 3 characters.' });
    const id = randomUUID(), createdAt = now(); db.prepare('INSERT INTO feedback (id,payload,status,created_at) VALUES (?,?,\'new\',?)').run(id, encrypt({ topic, message }), createdAt); return json(res, 201, { ok: true });
  }
  if (req.method === 'POST' && path === '/api/admin/login') {
    rateLimit(req, 'admin-login', 6, 15 * 60_000); const b = await readBody(req); const username = safeText(b.username, 100), password = typeof b.password === 'string' ? b.password : '';
    const candidate = passwordHash(password, ADMIN_PASSWORD_SALT);
    if (username !== ADMIN_USERNAME || !safeHashEqual(candidate, ADMIN_PASSWORD_HASH)) return json(res, 401, { error: 'Developer username or password is incorrect.' });
    const token = randomBytes(32).toString('base64url'), csrf = randomBytes(32).toString('base64url'), expires = new Date(Date.now() + ADMIN_SESSION_SECONDS * 1000).toISOString();
    db.prepare('INSERT INTO admin_sessions (token_hash,username,csrf_hash,expires_at) VALUES (?,?,?,?)').run(sha256(token), ADMIN_USERNAME, sha256(csrf), expires); cookie(res, ADMIN_COOKIE, token, ADMIN_SESSION_SECONDS); return json(res, 200, { ok: true, csrfToken: csrf });
  }
  if (req.method === 'GET' && path === '/api/admin/session') {
    const s = adminSession(req); if (!s) return json(res, 401, { authenticated: false });
    const csrf = randomBytes(32).toString('base64url'); db.prepare('UPDATE admin_sessions SET csrf_hash=? WHERE token_hash=?').run(sha256(csrf), s.token_hash); return json(res, 200, { authenticated: true, username: s.username, csrfToken: csrf });
  }
  if (path.startsWith('/api/admin/')) {
    const session = adminSession(req, req.method !== 'GET'); if (!session) return json(res, 401, { error: 'Developer sign-in required.' });
    if (req.method === 'GET' && path === '/api/admin/data') return json(res, 200, adminData());
    if (req.method === 'DELETE' && path === '/api/admin/consents') { const count = db.prepare('SELECT count(*) AS n FROM consent_events').get().n; db.prepare('DELETE FROM consent_events').run(); audit(session.username, 'consent_log_cleared', String(count)); return json(res, 200, { ok: true }); }
    if (req.method === 'POST' && path === '/api/admin/logout') {
      db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(session.token_hash); clearCookie(res, ADMIN_COOKIE); return json(res, 200, { ok: true });
    }
    const userMatch = path.match(/^\/api\/admin\/users\/([0-9a-f-]{36})$/i);
    if (userMatch && req.method === 'PATCH') {
      const id = userMatch[1], body = await readBody(req), existing = db.prepare('SELECT id FROM users WHERE id=?').get(id); if (!existing) return json(res, 404, { error: 'User not found.' });
      if (!['active','suspended'].includes(body.status) || typeof body.travelerVisible !== 'boolean') return json(res, 400, { error: 'Invalid user update.' });
      db.prepare('UPDATE users SET status=?,traveler_visible=? WHERE id=?').run(body.status, body.travelerVisible ? 1 : 0, id);
      if (body.status === 'suspended') db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(id);
      audit(session.username, body.status === 'suspended' ? 'user_suspended' : 'user_updated', id); return json(res, 200, { ok: true });
    }
    if (userMatch && req.method === 'DELETE') {
      const id = userMatch[1], existing = db.prepare('SELECT id FROM users WHERE id=?').get(id); if (!existing) return json(res, 404, { error: 'User not found.' });
      db.prepare('DELETE FROM users WHERE id=?').run(id); audit(session.username, 'user_deleted', id); return json(res, 200, { ok: true });
    }
    const feedbackMatch = path.match(/^\/api\/admin\/feedback\/([0-9a-f-]{36})$/i);
    if (feedbackMatch && req.method === 'PATCH') {
      const id = feedbackMatch[1], body = await readBody(req); if (!['new','reviewed'].includes(body.status)) return json(res, 400, { error: 'Invalid feedback status.' });
      db.prepare('UPDATE feedback SET status=? WHERE id=?').run(body.status, id); audit(session.username, `feedback_${body.status}`, id); return json(res, 200, { ok: true });
    }
    if (feedbackMatch && req.method === 'DELETE') {
      const id = feedbackMatch[1]; db.prepare('DELETE FROM feedback WHERE id=?').run(id); audit(session.username, 'feedback_deleted', id); return json(res, 200, { ok: true });
    }
    return json(res, 404, { error: 'Not found.' });
  }
  return json(res, 404, { error: 'Not found.' });
}

const server = createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.google.com https://www.recaptcha.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://www.gstatic.com https://www.google.com; connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com https://www.google.com https://www.recaptcha.net; frame-src https://www.google.com https://www.recaptcha.net; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
  try { await handle(req, res); }
  catch (error) { const status = error.status || 500; if (status === 500) console.error('Request failed:', error.message); if (!res.headersSent) json(res, status, { error: status === 500 ? 'The server could not complete that request.' : error.message }); else res.end(); }
});
server.listen(PORT, HOST, () => console.log(`Flight Friend is running at ${PUBLIC_ORIGIN} (bound to ${HOST}).`));
process.on('SIGINT', () => { db.close(); server.close(() => process.exit(0)); });
process.on('SIGTERM', () => { db.close(); server.close(() => process.exit(0)); });




