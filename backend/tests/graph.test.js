'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const Case = require('../src/models/Case');
const Content = require('../src/models/Content');
const AIAnalysisResult = require('../src/models/AIAnalysisResult');
const { MONGO_URI } = require('../src/config/env');

describe('Trust Graph & Score Propagation API Integration Tests', () => {
  let dbConnection;
  let testUser;
  let tokenUser;

  let contentRoot;
  let contentChild;
  let testCase;

  beforeAll(async () => {
    // Connect to test database
    dbConnection = await mongoose.connect(MONGO_URI);

    // Clear test collections
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await AIAnalysisResult.deleteMany({});

    // Create test user
    testUser = await User.create({
      name: 'Graph Analyst',
      email: 'analyst@test.com',
      password: 'password123',
      role: 'user',
      isActive: true,
    });

    // Login user to get token
    const loginUser = await request(app)
      .post('/api/auth/login')
      .send({ email: 'analyst@test.com', password: 'password123' });
    tokenUser = loginUser.body.accessToken;

    // 1. Create a root content document (Original)
    contentRoot = await Content.create({
      title: 'Original Node A',
      contentType: 'video',
      originalHash: 'a'.repeat(64),
      status: 'verified', // 100% confidence
      owner: testUser._id,
      derivationType: 'original',
      authenticityScore: 100,
      provenanceScore: 100,
      metadataRiskScore: 0,
      integrityVerificationScore: 100,
    });

    // 2. Create a child content document derived from root (AI Modified, link weight = 0.25)
    contentChild = await Content.create({
      title: 'Derived AI Node B',
      contentType: 'video',
      originalHash: 'b'.repeat(64),
      status: 'pending', // Pending with no analysis = 50% base confidence
      owner: testUser._id,
      parentId: contentRoot._id,
      derivationType: 'ai-modification',
      authenticityScore: 50,
      provenanceScore: 70, // Base score, but will be propagated dynamically
      metadataRiskScore: 75,
      integrityVerificationScore: 40,
    });

    // 3. Link child document to an active investigation Case
    testCase = await Case.create({
      title: 'Provenance Case Delta',
      createdBy: testUser._id,
      evidence: [contentChild._id],
      status: 'in-progress',
      severity: 'high',
    });
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await AIAnalysisResult.deleteMany({});
    await mongoose.connection.close();
  });

  describe('GET /api/content/:id/provenance', () => {
    it('returns nodes, links, and correct relationship weights', async () => {
      const res = await request(app)
        .get(`/api/content/${contentChild._id}/provenance`)
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);
      expect(res.body.nodes).toBeDefined();
      expect(res.body.links).toBeDefined();

      // Check links weight for 'ai-modification' (0.25)
      const derivationLink = res.body.links.find(
        (l) => l.source === contentRoot._id.toString() && l.target === contentChild._id.toString()
      );
      expect(derivationLink).toBeDefined();
      expect(derivationLink.type).toBe('ai-modification');
      expect(derivationLink.weight).toBe(0.25);
    });

    it('calculates and propagates confidence and trust scores down the derivation tree', async () => {
      const res = await request(app)
        .get(`/api/content/${contentChild._id}/provenance`)
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);

      const rootNode = res.body.nodes.find((n) => n.id === contentRoot._id.toString());
      const childNode = res.body.nodes.find((n) => n.id === contentChild._id.toString());

      expect(rootNode).toBeDefined();
      expect(childNode).toBeDefined();

      // Root node verification: Verified status = 100% confidence, Original = 100% provenance
      expect(rootNode.scores.confidence).toBe(100);
      expect(rootNode.scores.provenance).toBe(100);
      expect(rootNode.scores.trust).toBe(100);

      // Child node verification:
      // Link weight = 0.25
      // Expected Propagated Provenance = Root Provenance (100) * Link Weight (0.25) = 25
      // Base confidence of pending node B = 50.
      // Expected Propagated Confidence = Parent Conf (100) * Base Conf (50) / 100 = 50.
      expect(childNode.scores.provenance).toBe(25);
      expect(childNode.scores.confidence).toBe(50);

      // Expected trust = Math.round(((auth (50) * 0.4) + (provenance (25) * 0.4) + ((100 - ai (75)) * 0.2)) * (confidence (50) / 100))
      // auth * 0.4 = 20
      // provenance * 0.4 = 10
      // (100 - ai) * 0.2 = 25 * 0.2 = 5
      // Base trust calculation = 20 + 10 + 5 = 35
      // Trust scaled by confidence = 35 * 0.5 = 17.5 = 18
      expect(childNode.scores.trust).toBe(18);
    });

    it('integrates cases by appending case references to graph nodes', async () => {
      const res = await request(app)
        .get(`/api/content/${contentChild._id}/provenance`)
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);

      const childNode = res.body.nodes.find((n) => n.id === contentChild._id.toString());
      expect(childNode.activeCases).toBeDefined();
      expect(childNode.activeCases.length).toBe(1);
      expect(childNode.activeCases[0].title).toBe('Provenance Case Delta');
      expect(childNode.activeCases[0].status).toBe('in-progress');

      // Root node is not linked to cases
      const rootNode = res.body.nodes.find((n) => n.id === contentRoot._id.toString());
      expect(rootNode.activeCases.length).toBe(0);
    });
  });
});
