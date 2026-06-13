'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const Case = require('../src/models/Case');
const Content = require('../src/models/Content');
const AuditLog = require('../src/models/AuditLog');
const { MONGO_URI } = require('../src/config/env');

describe('Chain of Custody (AuditLog) API Integration Tests', () => {
  let dbConnection;
  let testUser1;
  let testUser2;
  let testMod;

  let tokenUser1;
  let tokenUser2;
  let tokenMod;

  beforeAll(async () => {
    // Connect to test database
    dbConnection = await mongoose.connect(MONGO_URI);

    // Clear test collections
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await AuditLog.deleteMany({});

    // Create test users
    testUser1 = await User.create({
      name: 'User One',
      email: 'user1@test.com',
      password: 'password123',
      role: 'user',
      isActive: true,
    });

    testUser2 = await User.create({
      name: 'User Two',
      email: 'user2@test.com',
      password: 'password123',
      role: 'user',
      isActive: true,
    });

    testMod = await User.create({
      name: 'Moderator One',
      email: 'mod@test.com',
      password: 'password123',
      role: 'moderator',
      isActive: true,
    });

    // Login users to get tokens
    const loginUser1 = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user1@test.com', password: 'password123' });
    tokenUser1 = loginUser1.body.accessToken;

    const loginUser2 = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user2@test.com', password: 'password123' });
    tokenUser2 = loginUser2.body.accessToken;

    const loginMod = await request(app)
      .post('/api/auth/login')
      .send({ email: 'mod@test.com', password: 'password123' });
    tokenMod = loginMod.body.accessToken;
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await AuditLog.deleteMany({});
    await mongoose.connection.close();
  });

  describe('Automatic Event Logging Integration', () => {
    it('automatically records content registration and links hashes cryptographically', async () => {
      // 1. Register content item A
      const contentRes = await request(app)
        .post('/api/content')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          title: 'Evidence File X',
          contentType: 'video',
          originalHash: 'c'.repeat(64),
        });

      expect(contentRes.status).toBe(201);
      const contentId = contentRes.body.content._id;

      // 2. Register content item B
      const contentResB = await request(app)
        .post('/api/content')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          title: 'Evidence File Y',
          contentType: 'image',
          originalHash: 'd'.repeat(64),
        });

      expect(contentResB.status).toBe(201);
      const contentIdB = contentResB.body.content._id;

      // 3. Inspect the resulting AuditLog entries
      const logs = await AuditLog.find().sort({ timestamp: 1 });

      // There should be exactly two logs: the two content-registered logs
      expect(logs.length).toBe(2);

      const regLog1 = logs.find((l) => l.action === 'content-registered' && String(l.entityId) === String(contentId));
      const regLog2 = logs.find((l) => l.action === 'content-registered' && String(l.entityId) === String(contentIdB));

      expect(regLog1).toBeDefined();
      expect(regLog2).toBeDefined();

      // Assert cryptographic linking: the previousLogHash of the second log must equal the hash of the first log
      expect(regLog2.previousLogHash).toBe(regLog1.hash);
    });

    it('automatically logs case events like case-created and case-note-added', async () => {
      // 1. Open a case
      const caseRes = await request(app)
        .post('/api/cases')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          title: 'Chain Verification Case Alpha',
          description: 'Investigating content tampering indicators',
          severity: 'medium',
        });

      expect(caseRes.status).toBe(201);
      const caseId = caseRes.body.case._id;

      // 2. Add an investigator note
      const noteRes = await request(app)
        .post(`/api/cases/${caseId}/notes`)
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({ text: 'Identified minor anomalies in verification history logs.' });

      expect(noteRes.status).toBe(200);

      // 3. Check logs database
      const caseLogs = await AuditLog.find({ entityId: caseId }).sort({ timestamp: 1 });
      expect(caseLogs.length).toBe(2);
      expect(caseLogs[0].action).toBe('case-created');
      expect(caseLogs[1].action).toBe('case-note-added');
      expect(caseLogs[1].previousLogHash).toBe(caseLogs[0].hash);
    });
  });

  describe('GET /api/audit (Audit Query Registry)', () => {
    it('returns a paginated list of system audit logs', async () => {
      const res = await request(app)
        .get('/api/audit?page=1&limit=5')
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      expect(res.body.logs).toBeDefined();
      expect(Array.isArray(res.body.logs)).toBe(true);
      expect(res.body.logs.length).toBeLessThanOrEqual(5);
      expect(res.body.pagination).toBeDefined();
      expect(res.body.logs[0].performedBy.name).toBeDefined(); // Populated user field
    });

    it('filters logs by action', async () => {
      const res = await request(app)
        .get('/api/audit?action=case-created')
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      const allCreated = res.body.logs.every((l) => l.action === 'case-created');
      expect(allCreated).toBe(true);
    });
  });

  describe('GET /api/audit/entity/:entityType/:entityId', () => {
    it('returns the history timeline for a specific case', async () => {
      // Find a case log
      const caseLog = await AuditLog.findOne({ entityType: 'Case' });
      expect(caseLog).toBeDefined();

      const res = await request(app)
        .get(`/api/audit/entity/Case/${caseLog.entityId}`)
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      expect(res.body.history).toBeDefined();
      expect(res.body.history.length).toBeGreaterThanOrEqual(1);
      expect(res.body.history[0].performedBy.name).toBeDefined();
    });
  });

  describe('GET /api/audit/verify (Cryptographic Integrity Audit)', () => {
    it('prevents regular users from triggering the verification check', async () => {
      const res = await request(app)
        .get('/api/audit/verify')
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(403);
    });

    it('allows administrators/moderators to verify chain integrity successfully on clean data', async () => {
      const res = await request(app)
        .get('/api/audit/verify')
        .set('Authorization', `Bearer ${tokenMod}`);

      expect(res.status).toBe(200);
      expect(res.body.verified).toBe(true);
      expect(res.body.compromisedLogsCount).toBe(0);
      expect(res.body.compromisedLogs.length).toBe(0);
    });

    it('flags integrity failure and returns compromised blocks if records are modified directly in the database', async () => {
      // Find a content registration log
      const targetLog = await AuditLog.findOne({ action: 'content-registered' });
      expect(targetLog).toBeDefined();

      // Tamper with details by updating direct fields in DB, bypassing logger logic
      await AuditLog.updateOne({ _id: targetLog._id }, { $set: { 'details.title': 'COMPROMISED EVIDENCE' } });

      // Run verification
      const res = await request(app)
        .get('/api/audit/verify')
        .set('Authorization', `Bearer ${tokenMod}`);

      expect(res.status).toBe(200);
      expect(res.body.verified).toBe(false);
      expect(res.body.compromisedLogsCount).toBeGreaterThanOrEqual(1);
      
      const compromisedIds = res.body.compromisedLogs.map((l) => l._id.toString());
      expect(compromisedIds).toContain(targetLog._id.toString());
    });
  });
});
