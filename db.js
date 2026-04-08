const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const { newDb, DataType } = require('pg-mem');

const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  database: process.env.DB_NAME || 'kendachi',
  user: process.env.DB_USER || 'kendachi',
  password: process.env.DB_PASSWORD || 'kendachi_secret',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
};

const useInMemoryDb = process.env.USE_IN_MEMORY_DB === 'true';
let pool = useInMemoryDb ? createInMemoryPool() : createPostgresPool();
let activeDbLabel = useInMemoryDb ? 'in-memory' : 'postgres';

function createPostgresPool() {
  const nextPool = new Pool(DB_CONFIG);
  nextPool.on('error', (err) => {
    console.error('[DB] Unexpected pool error:', err.message);
  });
  return nextPool;
}

function createInMemoryPool() {
  const mem = newDb({ autoCreateForeignKeyIndices: true });

  mem.public.registerEquivalentType({
    name: 'inet',
    equivalentTo: DataType.text,
    isValid: () => true,
  });

  mem.public.registerEquivalentType({
    name: 'jsonb',
    equivalentTo: DataType.text,
    isValid: () => true,
  });

  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  mem.public.none(schema);

  const { Pool: MemoryPool } = mem.adapters.createPg();
  return new MemoryPool();
}

async function switchToInMemoryDb(originalError) {
  console.warn('[DB] Falling back to in-memory database for local development.');
  if (originalError?.message) {
    console.warn(`[DB] Original connection error: ${originalError.message}`);
  }

  if (typeof pool?.end === 'function') {
    try {
      await pool.end();
    } catch (_) {}
  }

  pool = createInMemoryPool();
  activeDbLabel = 'in-memory';
}

async function verifyConnection() {
  const client = await pool.connect();
  try {
    const { rows } = await client.query('SELECT COUNT(*) FROM employees');
    console.log(`[DB] Connected (${activeDbLabel}) - ${rows[0].count} employee(s) in registry`);
  } finally {
    client.release();
  }
}

async function ensureMonitoringSchema() {
  const statements = [
    "ALTER TABLE otp_codes ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE otp_codes ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 4",
    "ALTER TABLE work_sessions ADD COLUMN activity_events INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE work_sessions ADD COLUMN idle_seconds INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE work_sessions ADD COLUMN hidden_seconds INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE work_sessions ADD COLUMN focus_loss_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE work_sessions ADD COLUMN presence_passes INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE work_sessions ADD COLUMN presence_failures INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE work_sessions ADD COLUMN monitoring_score INTEGER NOT NULL DEFAULT 100",
    "ALTER TABLE work_sessions ADD COLUMN auto_close_reason TEXT",
  ];

  for (const statement of statements) {
    try {
      await pool.query(statement);
    } catch (err) {
      if (!String(err.message || '').toLowerCase().includes('already exists')) {
        throw err;
      }
    }
  }
}

async function initDB() {
  try {
    await ensureMonitoringSchema();
    await verifyConnection();
  } catch (err) {
    if (!useInMemoryDb) {
      await switchToInMemoryDb(err);
      try {
        await ensureMonitoringSchema();
        await verifyConnection();
        return;
      } catch (fallbackErr) {
        console.error('[DB] In-memory fallback failed:', fallbackErr.message);
      }
    } else {
      console.error('[DB] In-memory initialization failed:', err.message);
    }

    console.error('     Make sure PostgreSQL is running and schema.sql was applied.');
    process.exit(1);
  }
}

async function query(text, params) {
  const start = Date.now();
  const result = await pool.query(text, params);
  const duration = Date.now() - start;
  if (process.env.NODE_ENV === 'development') {
    console.log(`[DB] ${duration}ms - ${text.substring(0, 60).replace(/\s+/g, ' ')}...`);
  }
  return result;
}

async function transaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, query, transaction, initDB };
