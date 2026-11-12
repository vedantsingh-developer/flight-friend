import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, scryptSync } from 'node:crypto';
const appDir = path.dirname(fileURLToPath(import.meta.url));
const envFile = path.join(appDir, '.env');
if (fs.existsSync(envFile)) throw new Error('.env already exists. Keep the existing encryption keys; do not overwrite them.');
const username = process.env.FF_SETUP_USERNAME || '';
const password = process.env.FF_SETUP_PASSWORD || '';
if (!/^[a-zA-Z0-9._-]{3,60}$/.test(username)) throw new Error('Developer username must be 3–60 letters, numbers, dots, underscores, or hyphens.');
if (password.length < 14 || password.length > 128) throw new Error('Developer password must be 14–128 characters.');
const salt = randomBytes(16), hash = scryptSync(password, salt, 64);
const lines = ['HOST=127.0.0.1','PORT=3000','PUBLIC_ORIGIN=http://localhost:3000','NODE_ENV=development',`ADMIN_USERNAME=${username}`,`ADMIN_PASSWORD_SALT=${salt.toString('hex')}`,`ADMIN_PASSWORD_HASH=${hash.toString('hex')}`,`DATA_ENCRYPTION_KEY=${randomBytes(32).toString('hex')}`,`LOOKUP_HMAC_KEY=${randomBytes(32).toString('hex')}`];
fs.writeFileSync(envFile, lines.join('\n')+'\n', { flag: 'wx', mode: 0o600 });
console.log('Developer access and encryption keys created. Your password was hashed and was not written to disk.');

