'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  createServer,
  extractInitialDataset,
  hashUploadPassword,
  initializeDatabase,
  validateRecords,
  verifyUploadPassword
} = require('../server');

test('el código JavaScript del tablero tiene sintaxis válida', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const script = html.match(/<script>\s*([\s\S]*?)<\/script>/);
  assert.ok(script);
  assert.doesNotThrow(() => new Function(script[1]));
});

test('extrae los datos base del tablero para inicializar una base vacía', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const records = extractInitialDataset(html);
  assert.ok(records.length > 0);
  assert.ok(records.every((record) => typeof record === 'object' && !Array.isArray(record)));
});

test('rechaza filas con campos desconocidos y datos no finitos', () => {
  assert.throws(() => validateRecords([{ p: 'Producto', arbitrary: 'valor' }]), /columna no permitida/);
  assert.throws(() => validateRecords([{ st: Number.POSITIVE_INFINITY }]), /debe ser finito/);
});

test('la contraseña se guarda como hash scrypt con sal y se verifica correctamente', async () => {
  const credential = await hashUploadPassword('DPCAN_SUPORT');
  assert.match(credential.salt, /^[a-f0-9]{32}$/);
  assert.match(credential.hash, /^[a-f0-9]{128}$/);
  assert.equal(await verifyUploadPassword('DPCAN_SUPORT', credential.salt, credential.hash), true);
  assert.equal(await verifyUploadPassword('otra-clave', credential.salt, credential.hash), false);
  assert.equal(await verifyUploadPassword(undefined, credential.salt, credential.hash), false);
});

test('Neon recibe solo sal y hash, no la contraseña legible', async () => {
  const queries = [];
  const pool = {
    async query(sql, params) {
      queries.push({ sql, params });
      if (sql.includes('SELECT') && sql.includes('sigmetas_dataset')) {
        throw new Error('La inicialización no debe leer ni sobrescribir los datos existentes.');
      }
      return { rows: [] };
    }
  };
  const records = [{ p: 'Producto inicial', i: 'Normostock' }];
  await initializeDatabase(pool, records, 'DPCAN_SUPORT');

  const credentialInsert = queries.find((query) => query.sql.includes('INSERT INTO sigmetas_admin_credential'));
  assert.ok(credentialInsert);
  assert.equal(credentialInsert.params.includes('DPCAN_SUPORT'), false);
  assert.match(credentialInsert.params[0], /^[a-f0-9]{32}$/);
  assert.match(credentialInsert.params[1], /^[a-f0-9]{128}$/);
});

test('la API permite leer datos y solo los reemplaza con la clave correcta', async (context) => {
  const credential = await hashUploadPassword('DPCAN_SUPORT');
  let dataset = {
    records: [{ p: 'Producto inicial', i: 'Normostock' }],
    has_qty: true,
    source_name: 'Inicial',
    updated_at: '2026-10-20T12:00:00.000Z'
  };
  const pool = {
    async query(sql, params) {
      if (sql.includes('SELECT records')) return { rows: [dataset] };
      if (sql.includes('SELECT password_salt')) {
        return { rows: [{ password_salt: credential.salt, password_hash: credential.hash }] };
      }
      if (sql.includes('INSERT INTO sigmetas_dataset')) {
        dataset = {
          records: JSON.parse(params[0]),
          has_qty: params[1],
          source_name: params[2],
          updated_at: '2026-10-20T12:30:00.000Z'
        };
        return { rows: [{ updated_at: dataset.updated_at }] };
      }
      throw new Error('Consulta inesperada en prueba.');
    }
  };
  const server = createServer({ pool });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/api/data`;

  const initialResponse = await fetch(url);
  assert.equal(initialResponse.status, 200);
  assert.equal((await initialResponse.json()).records[0].p, 'Producto inicial');

  const unauthorizedResponse = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Upload-Password': 'clave-incorrecta' },
    body: JSON.stringify({ records: [{ p: 'No autorizado' }], hasQty: false, sourceName: 'No autorizado' })
  });
  assert.equal(unauthorizedResponse.status, 401);
  assert.equal(dataset.records[0].p, 'Producto inicial');

  const savedResponse = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Upload-Password': 'DPCAN_SUPORT' },
    body: JSON.stringify({ records: [{ p: 'Producto nuevo' }], hasQty: false, sourceName: 'reporte.xlsx' })
  });
  assert.equal(savedResponse.status, 200);
  assert.equal(dataset.records[0].p, 'Producto nuevo');
  assert.equal(dataset.source_name, 'reporte.xlsx');
});

test('la API habilita preflight solo para el Static Site de SIGMETAS', async (context) => {
  const server = createServer({
    pool: { async query() { return { rows: [] }; } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  const url = `http://127.0.0.1:${server.address().port}/api/data`;

  const preflight = await fetch(url, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://sigmetas-1.onrender.com',
      'Access-Control-Request-Method': 'PUT',
      'Access-Control-Request-Headers': 'content-type,x-upload-password'
    }
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://sigmetas-1.onrender.com');
  assert.match(preflight.headers.get('access-control-allow-headers'), /X-Upload-Password/i);

  const blocked = await fetch(url, {
    method: 'OPTIONS',
    headers: { Origin: 'https://untrusted.example' }
  });
  assert.equal(blocked.status, 403);
});
