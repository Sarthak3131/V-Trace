'use strict';

// Mock pdf-parse and mammoth BEFORE importing app
jest.mock('pdf-parse', () => {
  return jest.fn().mockResolvedValue({
    text: 'verbatim plagiarized paragraph check. furthermore, moreover, delve. in conclusion, it is a pivotal testament.'
  });
});

jest.mock('mammoth', () => {
  return {
    extractRawText: jest.fn().mockResolvedValue({
      value: 'verbatim plagiarized paragraph check. furthermore, moreover, delve. in conclusion, it is a pivotal testament.'
    })
  };
});

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const PlagiarismDocument = require('../src/models/PlagiarismDocument');
const PlagiarismReport = require('../src/models/PlagiarismReport');
const { MONGO_URI } = require('../src/config/env');

describe('Enterprise Plagiarism Detection System API Integration Tests', () => {
  let dbConnection;
  let testUser1;
  let testUser2;
  let tokenUser1;
  let tokenUser2;
  let sourceDocId;
  let createdReportId;

  beforeAll(async () => {
    dbConnection = await mongoose.connect(MONGO_URI);
    
    // Clear collections
    await User.deleteMany({});
    await PlagiarismDocument.deleteMany({});
    await PlagiarismReport.deleteMany({});

    // Create test users
    testUser1 = await User.create({
      name: 'Plag Analyst One',
      email: 'plag1@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    testUser2 = await User.create({
      name: 'Plag Analyst Two',
      email: 'plag2@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    // Login users to get tokens
    const loginUser1 = await request(app)
      .post('/api/auth/login')
      .send({ email: 'plag1@test.com', password: 'password123' });
    tokenUser1 = loginUser1.body.accessToken;

    const loginUser2 = await request(app)
      .post('/api/auth/login')
      .send({ email: 'plag2@test.com', password: 'password123' });
    tokenUser2 = loginUser2.body.accessToken;

    // Seed a baseline document in the database to compare against
    const baseline = await PlagiarismDocument.create({
      title: 'Baseline Reference Standards',
      fileName: 'baseline.txt',
      rawText: 'verbatim plagiarized paragraph check. this is the source document context.',
      owner: testUser2._id // owned by other user
    });
    sourceDocId = baseline._id;
  });

  afterAll(async () => {
    await User.deleteMany({});
    await PlagiarismDocument.deleteMany({});
    await PlagiarismReport.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/plagiarism/check', () => {
    it('should successfully upload and audit a TXT file for plagiarism', async () => {
      const res = await request(app)
        .post('/api/plagiarism/check')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .field('title', 'Thesis Submission Check')
        .attach('docFile', Buffer.from('verbatim plagiarized paragraph check. this is some test text.'), 'thesis.txt');

      expect(res.status).toBe(201);
      expect(res.body.reportId).toBeDefined();
      expect(res.body.scores).toBeDefined();
      expect(res.body.scores.plagiarismIndex).toBeGreaterThanOrEqual(0);
      expect(res.body.scores.plagiarismIndex).toBeLessThanOrEqual(100);
      expect(res.body.matches).toBeDefined();
      expect(res.body.reportMarkdown).toBeDefined();
      
      // Store report ID for subsequent tests
      createdReportId = res.body.reportId;
    });

    it('should successfully analyze a PDF using mocked pdf-parse', async () => {
      const res = await request(app)
        .post('/api/plagiarism/check')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .field('title', 'PDF Plagiarism Check')
        .attach('docFile', Buffer.from('mock pdf content'), 'check.pdf');

      expect(res.status).toBe(201);
      expect(res.body.reportId).toBeDefined();
      // Should show high AI rewrite score due to transition buzzwords in pdf mock
      expect(res.body.scores.aiRewriteScore).toBeGreaterThanOrEqual(30);
    });

    it('should successfully analyze a DOCX using mocked mammoth', async () => {
      const res = await request(app)
        .post('/api/plagiarism/check')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .field('title', 'DOCX Plagiarism Check')
        .attach('docFile', Buffer.from('mock docx content'), 'check.docx');

      expect(res.status).toBe(201);
      expect(res.body.reportId).toBeDefined();
    });

    it('should fail if file payload is missing', async () => {
      const res = await request(app)
        .post('/api/plagiarism/check')
        .set('Authorization', `Bearer ${tokenUser1}`)
        .field('title', 'No File Thesis');

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/verification file is required/i);
    });
  });

  describe('GET /api/plagiarism/documents', () => {
    it('should retrieve my uploaded documents list', async () => {
      const res = await request(app)
        .get('/api/plagiarism/documents')
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.documents)).toBe(true);
      expect(res.body.documents.length).toBeGreaterThanOrEqual(1);
      expect(res.body.documents[0].fileName).toBeDefined();
    });
  });

  describe('GET /api/plagiarism/reports', () => {
    it('should retrieve my plagiarism reports list', async () => {
      const res = await request(app)
        .get('/api/plagiarism/reports')
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.reports)).toBe(true);
      expect(res.body.reports.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('GET /api/plagiarism/reports/:id', () => {
    it('should retrieve report details', async () => {
      const res = await request(app)
        .get(`/api/plagiarism/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      expect(res.body.report).toBeDefined();
      expect(res.body.report._id).toBe(createdReportId);
      expect(res.body.report.documentId).toBeDefined();
    });

    it('should block retrieval by unauthorized users', async () => {
      const res = await request(app)
        .get(`/api/plagiarism/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser2}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access denied/i);
    });

    it('should return 404 for invalid report IDs', async () => {
      const invalidId = new mongoose.Types.ObjectId();
      const res = await request(app)
        .get(`/api/plagiarism/reports/${invalidId}`)
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/report not found/i);
    });
  });

  describe('DELETE /api/plagiarism/reports/:id', () => {
    it('should block deletion by unauthorized users', async () => {
      const res = await request(app)
        .delete(`/api/plagiarism/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser2}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access denied/i);
    });

    it('should successfully delete a plagiarism report', async () => {
      const res = await request(app)
        .delete(`/api/plagiarism/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser1}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/deleted successfully/i);

      // Verify deletion
      const verify = await request(app)
        .get(`/api/plagiarism/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser1}`);
      expect(verify.status).toBe(404);
    });
  });
});
