'use strict';

// Mock the AI provider before imports
jest.mock('../src/utils/aiProvider', () => {
  const actual = jest.requireActual('../src/utils/aiProvider');
  return {
    ...actual,
    isProviderConfigured: jest.fn().mockImplementation(() => {
      // Allow overriding in tests
      return global.mockProviderConfigured !== undefined ? global.mockProviderConfigured : false;
    }),
    generateAIResponse: jest.fn().mockImplementation(async (systemPrompt, history, userMessage, structuredContext) => {
      const configured = global.mockProviderConfigured !== undefined ? global.mockProviderConfigured : false;
      if (!configured) {
        return `Offline mock response from mocked provider (length > 50 characters to pass the quality check)`;
      }
      if (userMessage.toLowerCase().includes('navigate')) {
        return 'I can take you to the cases section. [NAVIGATE:/cases] (length > 50 characters to pass the quality check)';
      }
      return 'Mocked AI Copilot Response from mocked provider (length > 50 characters to pass the quality check)';
    })
  };
});

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const Case = require('../src/models/Case');
const Content = require('../src/models/Content');
const AuditLog = require('../src/models/AuditLog');
const { MONGO_URI } = require('../src/config/env');

describe('V-Trace AI Copilot Endpoint Integration Tests', () => {
  let dbConnection;
  let testUser;
  let tokenUser;
  let createdCaseId;
  let createdEvidenceId;

  beforeAll(async () => {
    dbConnection = await mongoose.connect(MONGO_URI);

    // Clear collections
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await AuditLog.deleteMany({});

    // Create test user
    testUser = await User.create({
      name: 'Copilot Analyst',
      email: 'analyst@vtrace.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    // Login user to get token
    const loginUser = await request(app)
      .post('/api/auth/login')
      .send({ email: 'analyst@vtrace.com', password: 'password123' });
    tokenUser = loginUser.body.accessToken;

    // Create a dummy case
    const kase = await Case.create({
      title: 'Suspicious Document Case',
      description: 'Audit case for leaked credentials',
      status: 'in-progress',
      severity: 'high',
      createdBy: testUser._id
    });
    createdCaseId = kase._id.toString();

    // Create a dummy evidence content
    const content = await Content.create({
      title: 'leaked_contract.pdf',
      contentType: 'document',
      originalHash: 'd3b07384d113edec49eaa6238ad5ff00',
      status: 'flagged',
      owner: testUser._id,
      fileSize: 1024 * 100,
      mimeType: 'application/pdf',
      provenanceScore: 40,
      authenticityScore: 50,
      metadataRiskScore: 90,
      integrityVerificationScore: 50,
      verificationConfidence: 95
    });
    createdEvidenceId = content._id.toString();

    // Create a dummy audit log
    await AuditLog.create({
      action: 'verify-file',
      entityType: 'Content',
      entityId: content._id,
      performedBy: testUser._id,
      hash: 'abc123hash',
      previousLogHash: '000000000000000000'
    });
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await AuditLog.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/ai/chat', () => {
    it('should block unauthorized requests without a token', async () => {
      const res = await request(app)
        .post('/api/ai/chat')
        .send({ message: 'Hello AI Copilot' });

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/token/i);
    });

    it('should fall back to offline intelligence when provider is unconfigured', async () => {
      global.mockProviderConfigured = false;

      const res = await request(app)
        .post('/api/ai/chat')
        .set('Authorization', `Bearer ${tokenUser}`)
        .send({ message: 'Hello AI Copilot' });

      expect(res.status).toBe(200);
      expect(res.body.response).toBeDefined();
      expect(res.body.response).toMatch(/offline mock response/i);
    });

    it('should return AI response successfully when provider is mocked as configured', async () => {
      global.mockProviderConfigured = true;

      const res = await request(app)
        .post('/api/ai/chat')
        .set('Authorization', `Bearer ${tokenUser}`)
        .send({
          message: 'Hi V-Trace Copilot, tell me about active cases.',
          history: [{ role: 'user', content: 'hello' }, { role: 'model', content: 'hi there' }],
          caseId: createdCaseId,
          evidenceId: createdEvidenceId,
          currentRoute: '/dashboard'
        });

      expect(res.status).toBe(200);
      expect(res.body.response).toBeDefined();
      expect(res.body.response).toContain('Mocked AI Copilot Response');
    });

    it('should process navigation requests and return navigation triggers', async () => {
      global.mockProviderConfigured = true;

      const res = await request(app)
        .post('/api/ai/chat')
        .set('Authorization', `Bearer ${tokenUser}`)
        .send({
          message: 'Navigate me to cases page',
          currentRoute: '/dashboard'
        });

      expect(res.status).toBe(200);
      expect(res.body.response).toContain('[NAVIGATE:/cases]');
    });

    it('should fail if message field is missing', async () => {
      const res = await request(app)
        .post('/api/ai/chat')
        .set('Authorization', `Bearer ${tokenUser}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/message is required/i);
    });
  });

  describe('GET /api/ai/status', () => {
    it('should return provider status details', async () => {
      const res = await request(app)
        .get('/api/ai/status')
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBeDefined();
      expect(res.body.online).toBeDefined();
      expect(res.body.model).toBeDefined();
    });

    it('should block unauthorized requests for status', async () => {
      const res = await request(app).get('/api/ai/status');
      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/ai/debug', () => {
    it('should return debug details', async () => {
      // Send a message first to populate debug logs
      await request(app)
        .post('/api/ai/chat')
        .set('Authorization', `Bearer ${tokenUser}`)
        .send({
          message: 'Hi V-Trace Copilot, tell me about active cases.',
          currentRoute: '/dashboard'
        });

      const res = await request(app)
        .get('/api/ai/debug')
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBeDefined();
      expect(res.body.intent).toBeDefined();
      expect(res.body.route).toBeDefined();
      expect(res.body.selectedCase).toBeDefined();
      expect(res.body.selectedEvidence).toBeDefined();
      expect(res.body.atsLoaded).toBeDefined();
      expect(res.body.historyMessages).toBeDefined();
      expect(res.body.responseSource).toBeDefined();
    });

    it('should block unauthorized requests for debug', async () => {
      const res = await request(app).get('/api/ai/debug');
      expect(res.status).toBe(401);
    });
  });
});
