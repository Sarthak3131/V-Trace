'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const path = require('path');
const mongoose = require('mongoose');

const authRoutes = require('./routes/authRoutes');
const contentRoutes = require('./routes/contentRoutes');
const caseRoutes = require('./routes/caseRoutes');
const auditRoutes = require('./routes/auditRoutes');
const aiRoutes = require('./routes/aiRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const atsRoutes = require('./routes/atsRoutes');
const plagiarismRoutes = require('./routes/plagiarismRoutes');

const logger = require('./utils/logger');
const { metricsMiddleware } = require('./middleware/metrics');

const app = express();

function getAllowedOrigins() {
  const rawOrigins = process.env.ALLOWED_ORIGINS;
  if (!rawOrigins || rawOrigins.trim() === '') {
    return ['http://localhost:3000'];
  }

  return rawOrigins
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

const allowedOrigins = getAllowedOrigins();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
    statusCode: 429,
  })
);

// Register metrics collection middleware
app.use(metricsMiddleware);

// Stream HTTP requests to Winston logger
const logFormat = process.env.NODE_ENV === 'production' ? 'combined' : 'dev';
app.use(
  morgan(logFormat, {
    stream: {
      write: (message) => logger.info(message.trim()),
    },
  })
);

app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

app.use('/api/auth', authRoutes);
app.use('/api/content', contentRoutes);
app.use('/api/cases', caseRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/ats', atsRoutes);
app.use('/api/plagiarism', plagiarismRoutes);

app.get('/api/health', async (req, res) => {
  const isDatabaseConnected = mongoose.connection.readyState === 1;

  const health = {
    status: isDatabaseConnected ? 'ok' : 'error',
    timestamp: new Date(),
    uptime: process.uptime(),
    system: {
      memoryUsage: process.memoryUsage(),
      cpuLoad: process.cpuUsage(),
    },
    services: {
      database: {
        status: isDatabaseConnected ? 'connected' : 'disconnected',
        readyState: mongoose.connection.readyState,
      },
    },
  };

  // Check Redis status
  try {
    const { checkRedisConnection } = require('./utils/forensicQueue');
    const redisHost = process.env.REDIS_HOST || 'localhost';
    const redisPort = parseInt(process.env.REDIS_PORT || '6379', 10);
    const isRedisConnected = await checkRedisConnection(redisHost, redisPort);
    
    health.services.redis = {
      status: isRedisConnected ? 'connected' : 'disconnected',
      host: redisHost,
      port: redisPort,
    };
  } catch (err) {
    logger.warn('Failed to resolve Redis status for health check: %s', err.message);
    health.services.redis = {
      status: 'unknown',
      error: err.message,
    };
  }

  if (!isDatabaseConnected) {
    return res.status(503).json(health);
  }

  return res.status(200).json(health);
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  logger.error(err);

  const statusCode = err.status || err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res.status(statusCode).json({ error: message });
});

module.exports = app;
