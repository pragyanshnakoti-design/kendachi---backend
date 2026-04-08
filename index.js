require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { initDB } = require('./db');

const authRoutes = require('./routes/auth');
const sessionRoutes = require('./routes/session');
const overtimeRoutes = require('./routes/overtime');
const employeeRoutes = require('./routes/employee');
const managerRoutes = require('./routes/manager');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3001;
const allowVercelPreviews = process.env.ALLOW_VERCEL_PREVIEWS === 'true';
const allowedOrigins = new Set(
  [
    'http://localhost:5173',
    'http://localhost:4173',
    process.env.FRONTEND_URL,
    ...(process.env.FRONTEND_URLS || '').split(','),
  ]
    .map((value) => String(value || '').trim())
    .filter(Boolean)
);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }

    if (allowVercelPreviews && /^https:\/\/.+\.vercel\.app$/i.test(origin)) {
      return callback(null, true);
    }

    return callback(new Error('CORS origin not allowed'));
  },
  credentials: true,
}));
app.use(express.json());

app.set('trust proxy', 1);

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'kendachi-api',
    timestamp: new Date().toISOString(),
  });
});

app.use('/api/auth', authRoutes);
app.use('/api/session', sessionRoutes);
app.use('/api/overtime', overtimeRoutes);
app.use('/api/employee', employeeRoutes);
app.use('/api/manager', managerRoutes);
app.use('/api/admin', adminRoutes);

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
});

async function boot() {
  await initDB();
  app.listen(PORT, () => {
    console.log(`\n[SERVER] KENDACHI API listening on :${PORT}`);
  });
}

boot();
