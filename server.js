'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { promisify } = require('node:util');
const { randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const { Pool } = require('pg');

const ROOT = __dirname;
const INDEX_PATH = path.join(ROOT, 'index.html');
const MAX_BODY_BYTES = 25 * 1024 * 1024;
const MAX_RECORDS = 100000;
const PASSWORD_HASH_BYTES = 64;
const MAX_FAILED_ATTEMPTS = 10;
const FAILED_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const scryptAsync = promisify(scrypt);
const failedAttempts = new Map();
const ALLOWED_ORIGINS = new Set([
  'https://sigmetas-1.onrender.com',
  'https://sigmetas-api-dpcan.onrender.com'
]);
const ALLOWED_FIELDS = new Set([
  'r', 'd', 'e', 't', 'cat', 'p', 's', 'i', 'tp', 'cod', 'ip', 'ie',
  'dp', 'tpr', 'st', 'cp', 'md', 'c12', 'cma', 'sa', 'cu4', 'sar', 'pr', 'req'
]);

function extractInitialDataset(html) {
  html = html.replace(/\r\n/g, '\n');
  const startMarker = 'var RAW = ';
  const endMarker = ';\nvar DATA=RAW.map';
  const start = html.indexOf(startMarker);
  const end = html.indexOf(endMarker, start);
  if (start === -1 || end === -1) {
    throw new Error('No se encontró el conjunto inicial RAW en index.html.');
  }

  const records = JSON.parse(html.slice(start + startMarker.length, end));
  validateRecords(records);
  return records;
}

function validateRecords(records) {
  if (!Array.isArray(records) || records.length === 0 || records.length > MAX_RECORDS) {
    throw new Error(`El archivo debe contener entre 1 y ${MAX_RECORDS} registros.`);
  }

  for (const [index, record] of records.entries()) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error(`El registro ${index + 1} no tiene un formato válido.`);
    }
    for (const [field, value] of Object.entries(record)) {
      if (!ALLOWED_FIELDS.has(field)) {
        throw new Error(`El registro ${index + 1} contiene una columna no permitida.`);
      }
      if (value !== null && typeof value !== 'string' && typeof value !== 'number') {
        throw new Error(`El campo ${field} del registro ${index + 1} tiene un valor no válido.`);
      }
      if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new Error(`El campo ${field} del registro ${index + 1} debe ser finito.`);
      }
      if (typeof value === 'string' && value.length > 20000) {
        throw new Error(`El campo ${field} del registro ${index + 1} es demasiado largo.`);
      }
    }
  }
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(body));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
      } else if (!tooLarge) {
        chunks.push(chunk);
      }
    });
    request.on('error', reject);
    request.on('end', () => {
      if (tooLarge) {
        const error = new Error('La solicitud supera el límite de 25 MB.');
        error.statusCode = 413;
        reject(error);
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        const error = new Error('El cuerpo de la solicitud no contiene JSON válido.');
        error.statusCode = 400;
        reject(error);
      }
    });
  });
}

async function hashUploadPassword(password) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(password, salt, PASSWORD_HASH_BYTES);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

async function verifyUploadPassword(password, saltHex, hashHex) {
  if (typeof password !== 'string' || !/^[a-f0-9]{32}$/i.test(saltHex) ||
      !/^[a-f0-9]{128}$/i.test(hashHex)) {
    return false;
  }
  const expectedHash = Buffer.from(hashHex, 'hex');
  const actualHash = await scryptAsync(password, Buffer.from(saltHex, 'hex'), PASSWORD_HASH_BYTES);
  return timingSafeEqual(actualHash, expectedHash);
}

function isRateLimited(clientId) {
  const attempt = failedAttempts.get(clientId);
  if (!attempt) return false;
  if (attempt.expiresAt <= Date.now()) {
    failedAttempts.delete(clientId);
    return false;
  }
  return attempt.count >= MAX_FAILED_ATTEMPTS;
}

function recordFailedAttempt(clientId) {
  const now = Date.now();
  let attempt = failedAttempts.get(clientId);
  if (!attempt || attempt.expiresAt <= now) {
    attempt = { count: 0, expiresAt: now + FAILED_ATTEMPT_WINDOW_MS };
  }
  attempt.count += 1;
  failedAttempts.delete(clientId);
  failedAttempts.set(clientId, attempt);
  if (failedAttempts.size > 10000) {
    failedAttempts.delete(failedAttempts.keys().next().value);
  }
}

async function initializeDatabase(pool, initialRecords, uploadPassword) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sigmetas_dataset (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      records JSONB NOT NULL CHECK (jsonb_typeof(records) = 'array'),
      has_qty BOOLEAN NOT NULL,
      source_name TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `INSERT INTO sigmetas_dataset (id, records, has_qty, source_name)
     VALUES (1, $1::jsonb, TRUE, $2)
     ON CONFLICT (id) DO NOTHING`,
    [JSON.stringify(initialRecords), 'Datos base incluidos en SIGMETAS']
  );
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sigmetas_admin_credential (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  const credential = await hashUploadPassword(uploadPassword);
  await pool.query(
    `INSERT INTO sigmetas_admin_credential (id, password_salt, password_hash)
     VALUES (1, $1, $2)
     ON CONFLICT (id) DO UPDATE
     SET password_salt = EXCLUDED.password_salt,
         password_hash = EXCLUDED.password_hash,
         updated_at = NOW()`,
    [credential.salt, credential.hash]
  );
}

function createServer({ pool }) {
  return http.createServer(async (request, response) => {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    const origin = request.headers.origin;
    if (origin && ALLOWED_ORIGINS.has(origin)) {
      response.setHeader('Access-Control-Allow-Origin', origin);
      response.setHeader('Vary', 'Origin');
      if (request.method === 'OPTIONS') {
        response.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
        response.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Upload-Password');
        response.setHeader('Access-Control-Max-Age', '600');
      }
    }

    let pathname;
    try {
      pathname = new URL(request.url, 'http://localhost').pathname;
    } catch {
      sendJson(response, 400, { error: 'Ruta no válida.' });
      return;
    }

    try {
      if (pathname === '/api/data' && request.method === 'OPTIONS') {
        if (!origin || !ALLOWED_ORIGINS.has(origin)) {
          sendJson(response, 403, { error: 'Este origen no está autorizado.' });
          return;
        }
        response.writeHead(204);
        response.end();
        return;
      }

      if (pathname === '/api/health' && request.method === 'GET') {
        await pool.query('SELECT 1');
        sendJson(response, 200, { status: 'ok' });
        return;
      }

      if (pathname === '/api/data' && request.method === 'GET') {
        const result = await pool.query(
          'SELECT records, has_qty, source_name, updated_at FROM sigmetas_dataset WHERE id = 1'
        );
        if (!result.rows.length) {
          sendJson(response, 503, { error: 'Los datos iniciales aún no están disponibles.' });
          return;
        }
        const row = result.rows[0];
        sendJson(response, 200, {
          records: row.records,
          hasQty: row.has_qty,
          sourceName: row.source_name,
          updatedAt: row.updated_at
        });
        return;
      }

      if (pathname === '/api/data' && request.method === 'PUT') {
        const clientId = request.socket.remoteAddress || 'unknown';
        if (isRateLimited(clientId)) {
          sendJson(response, 429, { error: 'Demasiados intentos fallidos. Intente de nuevo en 15 minutos.' });
          return;
        }
        const credentialResult = await pool.query(
          'SELECT password_salt, password_hash FROM sigmetas_admin_credential WHERE id = 1'
        );
        if (!credentialResult.rows.length) {
          sendJson(response, 503, { error: 'La clave de responsable aún no está configurada.' });
          return;
        }
        const authorized = await verifyUploadPassword(
          request.headers['x-upload-password'],
          credentialResult.rows[0].password_salt,
          credentialResult.rows[0].password_hash
        );
        if (!authorized) {
          recordFailedAttempt(clientId);
          sendJson(response, 401, { error: 'Clave de responsable incorrecta.' });
          return;
        }
        failedAttempts.delete(clientId);
        const body = await readJson(request);
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          sendJson(response, 400, { error: 'El cuerpo de la solicitud no tiene un formato válido.' });
          return;
        }
        validateRecords(body.records);
        if (typeof body.hasQty !== 'boolean') {
          sendJson(response, 400, { error: 'El indicador de datos cuantitativos no es válido.' });
          return;
        }
        if (typeof body.sourceName !== 'string' || !body.sourceName.trim() || body.sourceName.length > 255) {
          sendJson(response, 400, { error: 'El nombre del archivo no es válido.' });
          return;
        }
        const result = await pool.query(
          `INSERT INTO sigmetas_dataset (id, records, has_qty, source_name, updated_at)
           VALUES (1, $1::jsonb, $2, $3, NOW())
           ON CONFLICT (id) DO UPDATE
           SET records = EXCLUDED.records,
               has_qty = EXCLUDED.has_qty,
               source_name = EXCLUDED.source_name,
               updated_at = EXCLUDED.updated_at
           RETURNING updated_at`,
          [JSON.stringify(body.records), body.hasQty, body.sourceName.trim()]
        );
        sendJson(response, 200, { updatedAt: result.rows[0].updated_at });
        return;
      }

      if (pathname === '/' || pathname === '/index.html') {
        response.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'strict-origin-when-cross-origin'
        });
        fs.createReadStream(INDEX_PATH).pipe(response);
        return;
      }

      sendJson(response, 404, { error: 'Recurso no encontrado.' });
    } catch (error) {
      console.error('Error al atender la solicitud:', error);
      if (!response.headersSent) {
        sendJson(response, error.statusCode || 500, {
          error: error.statusCode ? error.message : 'No fue posible completar la operación.'
        });
      } else {
        response.destroy(error);
      }
    }
  });
}

async function start() {
  const connectionString = process.env.DATABASE_URL;
  const uploadPassword = process.env.UPLOAD_PASSWORD || process.env.ADMIN_WRITE_KEY;
  if (!connectionString) {
    throw new Error('Falta configurar DATABASE_URL con la cadena de conexión de Neon.');
  }
  if (!uploadPassword) {
    throw new Error('Falta configurar UPLOAD_PASSWORD con la clave de responsable.');
  }

  const pool = new Pool({
    connectionString,
    max: 5,
    connectionTimeoutMillis: 10000
  });
  const initialRecords = extractInitialDataset(fs.readFileSync(INDEX_PATH, 'utf8'));
  await initializeDatabase(pool, initialRecords, uploadPassword);

  const server = createServer({ pool });
  const port = Number(process.env.PORT || 3000);
  server.listen(port, '0.0.0.0', () => {
    console.log(`SIGMETAS disponible en el puerto ${port}.`);
  });
  server.on('close', () => pool.end());
}

if (require.main === module) {
  start().catch((error) => {
    console.error('No se pudo iniciar SIGMETAS:', error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  createServer,
  extractInitialDataset,
  hashUploadPassword,
  initializeDatabase,
  validateRecords,
  verifyUploadPassword
};
