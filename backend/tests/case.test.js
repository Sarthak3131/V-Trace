'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const Case = require('../src/models/Case');
const Content = require('../src/models/Content');
const { MONGO_URI } = require('../src/config/env');

describe('Case Management API Integration Tests', () => {
  let dbConnection;
  let testUser1;
  let testUser2;
  let testMod;
  
  let tokenUser1;
  let tokenUser2;
  let tokenMod;

  let testContent;

  beforeAll(async () => {
    // Connect to test database
    dbConnection = await mongoose.connect(MONGO_URI);
    
    // Clear test collections
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});

    // Create test users
    testUser1 = await User.create({
      name: 'User One',
      email: 'user1@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    testUser2 = await User.create({
      name: 'User Two',
      email: 'user2@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    testMod = await User.create({
      name: 'Moderator One',
      email: 'mod@test.com',
      password: 'password123',
      role: 'moderator',
      isActive: true
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

    // Create test content
    testContent = await Content.create({
      title: 'Evidence Item A',
      contentType: 'image',
      originalHash: 'b'.repeat(64),
      owner: testUser1._id
    });
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/cases', () => {
    it('allows a regular user to create a case', async () => {
      const res = await request(app)
        .post('/api/cases')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          title: 'Tamper Case Alpha',
          description: 'Investigating suspected splicing',
          severity: 'high'
        });

      expect(res.status).toBe(201);
      expect(res.body.case).toBeDefined();
      expect(res.body.case.title).toBe('Tamper Case Alpha');
      expect(res.body.case.status).toBe('open');
      expect(res.body.case.severity).toBe('high');
      expect(res.body.case.createdBy.name).toBe('User One');
    });

    it('rejects case creation with invalid titles', async () => {
      const res = await request(app)
        .post('/api/cases')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          title: 'Ta',
          description: 'Too short'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/at least 3 characters/i);
    });

    it('prevents regular users from assigning cases to others', async () => {
      const res = await request(app)
        .post('/api/cases')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          title: 'Unauthorized Assign',
          assignedTo: testUser2._id.toString()
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/only admins or moderators/i);
    });

    it('allows moderators to assign cases to anyone', async () => {
      const res = await request(app)
        .post('/api/cases')
        .set('Authorization', `Bearer ${tokenMod}`)
        .send({
          title: 'Moderator Assigned Case',
          assignedTo: testUser1._id.toString()
        });

      expect(res.status).toBe(201);
      expect(res.body.case.assignedTo.name).toBe('User One');
    });
  });

  describe('GET /api/cases', () => {
    let user1Case;
    let user2Case;
    let modCase;

    beforeAll(async () => {
      await Case.deleteMany({});
      
      user1Case = await Case.create({
        title: 'User 1 Case',
        createdBy: testUser1._id,
        severity: 'low',
        status: 'open'
      });

      user2Case = await Case.create({
        title: 'User 2 Case',
        createdBy: testUser2._id,
        severity: 'high',
        status: 'open'
      });

      modCase = await Case.create({
        title: 'Mod Assigned to User 1',
        createdBy: testMod._id,
        assignedTo: testUser1._id,
        severity: 'critical',
        status: 'in-progress'
      });
    });

    it('returns only created or assigned cases for user 1', async () => {
      const res = await request(app)
        .get('/api/cases')
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      expect(res.body.cases.length).toBe(2);
      
      const titles = res.body.cases.map(c => c.title);
      expect(titles).toContain('User 1 Case');
      expect(titles).toContain('Mod Assigned to User 1');
      expect(titles).not.toContain('User 2 Case');
    });

    it('returns all cases for a moderator', async () => {
      const res = await request(app)
        .get('/api/cases')
        .set('Authorization', `Bearer ${tokenMod}`);

      expect(res.status).toBe(200);
      expect(res.body.cases.length).toBe(3);
    });

    it('filters cases by status query param', async () => {
      const res = await request(app)
        .get('/api/cases?status=in-progress')
        .set('Authorization', `Bearer ${tokenMod}`);

      expect(res.status).toBe(200);
      expect(res.body.cases.length).toBe(1);
      expect(res.body.cases[0].title).toBe('Mod Assigned to User 1');
    });
  });

  describe('PATCH /api/cases/:id', () => {
    let testCase;

    beforeEach(async () => {
      await Case.deleteMany({});
      testCase = await Case.create({
        title: 'Update Test Case',
        description: 'Original description',
        status: 'open',
        severity: 'medium',
        createdBy: testUser1._id,
        history: []
      });
    });

    it('denies access if user is not owner, assignee, or moderator', async () => {
      const res = await request(app)
        .patch(`/api/cases/${testCase._id}`)
        .set('Authorization', `Bearer ${tokenUser2}`)
        .send({ status: 'in-progress' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access denied/i);
    });

    it('allows owner to update status, severity and description and writes audit logs', async () => {
      const res = await request(app)
        .patch(`/api/cases/${testCase._id}`)
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          status: 'resolved',
          severity: 'high',
          description: 'Updated description'
        });

      expect(res.status).toBe(200);
      expect(res.body.case.status).toBe('resolved');
      expect(res.body.case.severity).toBe('high');
      expect(res.body.case.description).toBe('Updated description');

      // Assert history logs were written
      const historyActions = res.body.case.history.map(h => h.action);
      expect(historyActions).toContain('status-changed');
      expect(historyActions).toContain('severity-changed');
      expect(historyActions).toContain('description-updated');
    });
  });

  describe('Case note logging and evidence linkages', () => {
    let testCase;

    beforeAll(async () => {
      await Case.deleteMany({});
      testCase = await Case.create({
        title: 'Notes & Evidence Case',
        createdBy: testUser1._id,
        evidence: [],
        notes: [],
        history: []
      });
    });

    it('adds investigator notes and tracks in history', async () => {
      const res = await request(app)
        .post(`/api/cases/${testCase._id}/notes`)
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({ text: 'Speech patterns indicate vocoder artefacts on frame 12.' });

      expect(res.status).toBe(200);
      expect(res.body.case.notes.length).toBe(1);
      expect(res.body.case.notes[0].text).toBe('Speech patterns indicate vocoder artefacts on frame 12.');
      expect(res.body.case.notes[0].createdBy.name).toBe('User One');

      const historyActions = res.body.case.history.map(h => h.action);
      expect(historyActions).toContain('note-added');
    });

    it('links and unlinks evidence items and tracks in history', async () => {
      // 1. Link Evidence
      const linkRes = await request(app)
        .post(`/api/cases/${testCase._id}/evidence`)
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          contentId: testContent._id.toString(),
          action: 'link'
        });

      expect(linkRes.status).toBe(200);
      expect(linkRes.body.case.evidence.length).toBe(1);
      expect(linkRes.body.case.evidence[0]._id).toBe(testContent._id.toString());
      expect(linkRes.body.case.history.map(h => h.action)).toContain('evidence-linked');

      // 2. Unlink Evidence
      const unlinkRes = await request(app)
        .post(`/api/cases/${testCase._id}/evidence`)
        .set('Authorization', `Bearer ${tokenUser1}`)
        .send({
          contentId: testContent._id.toString(),
          action: 'unlink'
        });

      expect(unlinkRes.status).toBe(200);
      expect(unlinkRes.body.case.evidence.length).toBe(0);
      expect(unlinkRes.body.case.history.map(h => h.action)).toContain('evidence-unlinked');
    });
  });
});
