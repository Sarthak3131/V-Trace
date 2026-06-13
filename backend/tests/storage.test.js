'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const app = require('../src/app');
const User = require('../src/models/User');
const { MONGO_URI } = require('../src/config/env');

describe('Storage & Upload Integration Tests', () => {
  let dbConnection;
  let testUser;
  let userToken;

  beforeAll(async () => {
    // Connect to test database
    dbConnection = await mongoose.connect(MONGO_URI);
    
    // Clear test users
    await User.deleteMany({});

    // Create test user
    testUser = await User.create({
      name: 'Test Storage User',
      email: 'storage@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    // Login user
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'storage@test.com', password: 'password123' });
    
    userToken = loginRes.body.accessToken;
  });

  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/content/upload-params', () => {
    it('returns 401 if request is unauthenticated', async () => {
      const res = await request(app)
        .post('/api/content/upload-params')
        .send({ fileName: 'test.png', fileType: 'image/png' });

      expect(res.status).toBe(401);
    });

    it('returns 400 if fileName or fileType is missing', async () => {
      const res = await request(app)
        .post('/api/content/upload-params')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ fileName: 'test.png' });

      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body.errors)).toMatch(/fileType/i);
    });

    it('returns valid upload parameters config shape', async () => {
      const res = await request(app)
        .post('/api/content/upload-params')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ fileName: 'test.png', fileType: 'image/png' });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBeDefined();
      expect(res.body.uploadUrl).toBeDefined();
      expect(res.body.downloadUrl).toBeDefined();
      expect(res.body.key).toBeDefined();
      expect(res.body.method).toBeDefined();
      expect(res.body.headers).toBeDefined();
    });
  });

  describe('POST /api/content/upload-local', () => {
    let uploadedFileKey = null;

    it('returns 401 if request is unauthenticated', async () => {
      const res = await request(app)
        .post('/api/content/upload-local')
        .attach('file', Buffer.from('mock content'), 'test.txt');

      expect(res.status).toBe(401);
    });

    it('successfully uploads and stores file locally', async () => {
      const customKey = `test-${Date.now()}.txt`;
      const res = await request(app)
        .post('/api/content/upload-local')
        .set('Authorization', `Bearer ${userToken}`)
        .field('key', customKey)
        .attach('file', Buffer.from('mock content text'), 'test.txt');

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/success/i);
      expect(res.body.key).toBe(customKey);
      expect(res.body.downloadUrl).toMatch(new RegExp(`/uploads/${customKey}`));

      uploadedFileKey = res.body.key;

      // Verify file exists on disk
      const filePath = path.join(__dirname, '../uploads', customKey);
      expect(fs.existsSync(filePath)).toBe(true);
      expect(fs.readFileSync(filePath, 'utf8')).toBe('mock content text');
    });

    afterAll(() => {
      if (uploadedFileKey) {
        const filePath = path.join(__dirname, '../uploads', uploadedFileKey);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }
    });
  });
});
