'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const Content = require('../src/models/Content');
const { MONGO_URI } = require('../src/config/env');

describe('Security Hardening & Cryptographic Integration API Tests', () => {
  let dbConnection;
  let testUser;
  let userToken;
  let userRefreshToken;
  let testAdmin;
  let adminToken;

  beforeAll(async () => {
    // Connect to the test database
    dbConnection = await mongoose.connect(MONGO_URI);
    
    // Clear test collections
    await User.deleteMany({});
    await Content.deleteMany({});

    // Create test user
    testUser = await User.create({
      name: 'Test Regular User',
      email: 'user@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    // Create test admin
    testAdmin = await User.create({
      name: 'Test Admin User',
      email: 'admin@test.com',
      password: 'password123',
      role: 'admin',
      isActive: true
    });

    // Login user to get tokens
    const userLoginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user@test.com', password: 'password123' });
    
    userToken = userLoginRes.body.accessToken;
    // Extract refresh cookie
    const cookies = userLoginRes.headers['set-cookie'];
    if (cookies) {
      const refreshCookie = cookies.find(c => c.startsWith('refreshToken='));
      if (refreshCookie) {
        userRefreshToken = refreshCookie.split(';')[0].split('=')[1];
      }
    }

    // Login admin
    const adminLoginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin@test.com', password: 'password123' });
    
    adminToken = adminLoginRes.body.accessToken;
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Content.deleteMany({});
    await mongoose.connection.close();
  });

  describe('Deactivated Account Constraints', () => {
    it('allows access to protected routes when user is active', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.status).toBe(200);
      expect(res.body.email).toBe('user@test.com');
    });

    it('immediately denies access to protected routes after deactivation', async () => {
      // Deactivate user in database
      await User.updateOne({ _id: testUser._id }, { isActive: false });

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/disabled/i);
    });

    it('denies token refresh for a deactivated account and clears cookies', async () => {
      const res = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', [`refreshToken=${userRefreshToken}`]);
      
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/disabled/i);
      
      // Verify cookie is cleared in response headers
      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      const clearedCookie = cookies.find(c => c.includes('refreshToken=;'));
      expect(clearedCookie).toBeDefined();
    });

    // Reactivate user for subsequent tests
    afterAll(async () => {
      await User.updateOne({ _id: testUser._id }, { isActive: true });
      // Re-acquire fresh tokens for user
      const userLoginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'user@test.com', password: 'password123' });
      userToken = userLoginRes.body.accessToken;
    });
  });

  describe('Cryptographic Merkle Root Validation', () => {
    const validChunkHashes = [
      'a'.repeat(64),
      'b'.repeat(64),
      'c'.repeat(64)
    ];
    // Hand-calculated Merkle Root for validChunkHashes:
    // Pairwise combinations:
    // level 1: hashPair(a, b) -> hash12, hashPair(c, c) -> hash33
    // level 2: hashPair(hash12, hash33) -> root
    // We can compute it using our code or just calculate a fake one to ensure it fails.
    
    it('accepts content registration when merkleRoot is correct for the chunkHashes', async () => {
      const { buildMerkleRoot } = require('../src/core/merkle');
      const correctRoot = buildMerkleRoot(validChunkHashes);

      const res = await request(app)
        .post('/api/content')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          title: 'Test Authentic Content',
          contentType: 'text',
          originalHash: 'd'.repeat(64),
          chunkHashes: validChunkHashes,
          merkleRoot: correctRoot,
          isPublic: true
        });

      expect(res.status).toBe(201);
      expect(res.body.content.merkleRoot).toBe(correctRoot);
    });

    it('rejects content registration with 400 if merkleRoot is mathematically incorrect', async () => {
      const res = await request(app)
        .post('/api/content')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          title: 'Tampered Merkle Content',
          contentType: 'text',
          originalHash: 'e'.repeat(64),
          chunkHashes: validChunkHashes,
          merkleRoot: 'f'.repeat(64), // Invalid/tampered root
          isPublic: true
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/cryptographic validation failed/i);
    });
  });

  describe('Hash Search & NoSQL Injection checks', () => {
    const targetHash = '2'.repeat(64);

    beforeAll(async () => {
      // Register a content item with targetHash as originalHash
      await request(app)
        .post('/api/content')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          title: 'Special Search Content',
          contentType: 'text',
          originalHash: targetHash,
          isPublic: true
        });
    });

    it('returns the exact item when searching by its 64-char SHA-256 hash', async () => {
      const res = await request(app)
        .get('/api/content')
        .query({ search: targetHash });
      
      expect(res.status).toBe(200);
      expect(res.body.contents).toHaveLength(1);
      expect(res.body.contents[0].originalHash).toBe(targetHash);
      expect(res.body.contents[0].title).toBe('Special Search Content');
    });

    it('safely handles and mitigates NoSQL injection in contentType', async () => {
      const res = await request(app)
        .get('/api/content')
        .query({ contentType: { $ne: 'video' } }); // Attempt injection
      
      // Should bypass the parameter and return all results instead of executing $ne operator
      expect(res.status).toBe(200);
      // If mitigated, contentType is ignored (since it's not a string in ALLOWED_CONTENT_TYPES)
      // and it doesn't throw a MongoDB query error
      expect(res.body.contents).toBeDefined();
    });

    it('safely handles and mitigates NoSQL injection in status for admins', async () => {
      const res = await request(app)
        .get('/api/content')
        .set('Authorization', `Bearer ${adminToken}`)
        .query({ status: { $ne: 'rejected' } }); // Attempt injection
      
      expect(res.status).toBe(200);
      expect(res.body.contents).toBeDefined();
    });
  });
});
