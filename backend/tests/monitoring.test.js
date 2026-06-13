'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const { MONGO_URI } = require('../src/config/env');

describe('Production Monitoring API Integration Tests', () => {
  let dbConnection;
  let testAdmin;
  let testUser;
  let tokenAdmin;
  let tokenUser;

  beforeAll(async () => {
    dbConnection = await mongoose.connect(MONGO_URI);

    await User.deleteMany({});

    testAdmin = await User.create({
      name: 'System Admin',
      email: 'admin-monitor@test.com',
      password: 'password123',
      role: 'admin',
      isActive: true,
    });

    testUser = await User.create({
      name: 'Normal User',
      email: 'user-monitor@test.com',
      password: 'password123',
      role: 'user',
      isActive: true,
    });

    // Login users to get tokens
    const loginAdmin = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin-monitor@test.com', password: 'password123' });
    tokenAdmin = loginAdmin.body.accessToken;

    const loginUser = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user-monitor@test.com', password: 'password123' });
    tokenUser = loginUser.body.accessToken;
  });

  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('GET /api/health (Diagnostic Health Check)', () => {
    it('returns 200 OK and detailed service checks', async () => {
      const res = await request(app).get('/api/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.uptime).toBeGreaterThan(0);
      expect(res.body.system).toBeDefined();
      expect(res.body.system.memoryUsage).toBeDefined();
      expect(res.body.system.cpuLoad).toBeDefined();
      expect(res.body.services).toBeDefined();
      expect(res.body.services.database.status).toBe('connected');
      expect(res.body.services.redis).toBeDefined();
    });
  });

  describe('GET /api/audit/metrics (System Performance Metrics)', () => {
    it('blocks unauthenticated requests', async () => {
      const res = await request(app).get('/api/audit/metrics');
      expect(res.status).toBe(401);
    });

    it('blocks regular non-admin users from accessing metrics', async () => {
      const res = await request(app)
        .get('/api/audit/metrics')
        .set('Authorization', `Bearer ${tokenUser}`);
      expect(res.status).toBe(403);
    });

    it('allows admins to fetch db stats and traffic logs', async () => {
      // Trigger a couple of mock requests first to populate metrics
      await request(app).get('/api/health');

      const res = await request(app)
        .get('/api/audit/metrics')
        .set('Authorization', `Bearer ${tokenAdmin}`);

      expect(res.status).toBe(200);
      expect(res.body.dbStats).toBeDefined();
      expect(res.body.dbStats.totalUsers).toBeGreaterThanOrEqual(2);
      expect(res.body.trafficStats).toBeDefined();
      expect(res.body.trafficStats.totalRequests).toBeGreaterThanOrEqual(1);
      expect(res.body.trafficStats.avgResponseTimeMs).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(res.body.trafficStats.routeBreakdown)).toBe(true);
    });
  });
});
