'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { timingSafeEqual } = require('node:crypto');
const { Pool } = require('pg');

const ROOT = __dirname;
const INDEX_PATH = path.join(ROOT, 'index.html');
const MAX_BODY_BYTES = 25 * 1024 * 1024;
const MAX_RECORDS = 100000;
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

function validAdminKey(candidate, expected) {
  if (typeof candidate !== 'string' || Buffer.byteLength(candidate) !== Buffer.byteLength(expected)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(candidate), Buffer.from(expected));
}

async function initializeDatabase(pool, initialRecords) {
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
}

function createServer({ pool, adminKey }) {
  return http.createServer(async (request, response) => {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    let pathname;
    try {
      pathname = new URL(request.url, 'http://localhost').pathname;
    } catch {
      sendJson(response, 400, { error: 'Ruta no válida.' });
      return;
    }

    try {
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
        if (!validAdminKey(request.headers['x-admin-key'], adminKey)) {
          sendJson(response, 401, { error: 'Se requiere una clave de responsable válida.' });
          return;
        }
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
  const adminKey = process.env.ADMIN_WRITE_KEY;
  if (!connectionString) {
    throw new Error('Falta configurar DATABASE_URL con la cadena de conexión de Neon.');
  }
  if (!adminKey || Buffer.byteLength(adminKey) < 32) {
    throw new Error('ADMIN_WRITE_KEY debe configurarse con una clave aleatoria de al menos 32 caracteres.');
  }

  const pool = new Pool({
    connectionString,
    max: 5,
    connectionTimeoutMillis: 10000
  });
  const initialRecords = extractInitialDataset(fs.readFileSync(INDEX_PATH, 'utf8'));
  await initializeDatabase(pool, initialRecords);

  const server = createServer({ pool, adminKey });
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

module.exports = { createServer, extractInitialDataset, initializeDatabase, validAdminKey, validateRecords };
