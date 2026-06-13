'use strict';

const mongoose = require('mongoose');
const { forensicQueue, checkRedisConnection } = require('../src/utils/forensicQueue');
const User = require('../src/models/User');
const Content = require('../src/models/Content');
const AIAnalysisResult = require('../src/models/AIAnalysisResult');
const { MONGO_URI } = require('../src/config/env');

describe('Queue Integration & Fallback Tests', () => {
  let dbConnection;
  let testUser;

  beforeAll(async () => {
    dbConnection = await mongoose.connect(MONGO_URI);

    await User.deleteMany({});
    await Content.deleteMany({});
    await AIAnalysisResult.deleteMany({});

    testUser = await User.create({
      name: 'Queue Test User',
      email: 'queue@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Content.deleteMany({});
    await AIAnalysisResult.deleteMany({});
    await mongoose.connection.close();
  });

  it('verifies checkRedisConnection helper returns boolean false for invalid port/host', async () => {
    const isUp = await checkRedisConnection('localhost', 9999, 100);
    expect(typeof isUp).toBe('boolean');
    expect(isUp).toBe(false);
  });

  it('runs enqueuing in fallback mode (when Redis is down)', async () => {
    // Register test content
    const content = await Content.create({
      title: 'Queue Test Image',
      description: 'Image upload for queue testing',
      contentType: 'image',
      originalHash: 'a'.repeat(64),
      merkleRoot: 'a'.repeat(64),
      chunkHashes: ['a'.repeat(64)],
      fileSize: 100,
      mimeType: 'image/png',
      owner: testUser._id,
      derivationType: 'original'
    });

    // Wait for forensic queue initialization promise
    await forensicQueue.waitForInit();

    // Trigger enqueue
    const job = await forensicQueue.add(content._id.toString());

    // Fallback mode is active because no Redis is online on local testing
    expect(forensicQueue.isBullMQ()).toBe(false);
    expect(job).toBeDefined();
    expect(job.contentId).toBe(content._id.toString());

    // Since NODE_ENV === 'test', fallback execution completes synchronously.
    // Verify AIAnalysisResult exists and is completed.
    const analysis = await AIAnalysisResult.findOne({ contentId: content._id });
    expect(analysis).toBeDefined();
    expect(analysis.status).toBe('completed');
    expect(analysis.metadataRiskScore).toBe(0); // 'original' image fallback base risk is 0 in test mode
    expect(analysis.analysisLogs.length).toBeGreaterThan(0);
    expect(analysis.forensicReport).toMatch(/Executive Summary/i);

    // Verify parent Content document is updated to verified status
    const updatedContent = await Content.findById(content._id);
    expect(updatedContent.status).toBe('verified');
    expect(updatedContent.authenticityScore).toBe(100);
    expect(updatedContent.integrityVerificationScore).toBe(100); // 100 - risk(0) = 100
  });
});
