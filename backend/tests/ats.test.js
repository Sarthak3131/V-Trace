'use strict';

// Mock pdf-parse and mammoth BEFORE importing app
jest.mock('pdf-parse', () => {
  return jest.fn().mockResolvedValue({
    text: 'mocked pdf text with javascript python docker aws react education experience skills projects email: test@example.com phone: 123-456-7890 link: http://github.com/test achievements: improved latency by 30% led managed designed'
  });
});

jest.mock('mammoth', () => {
  return {
    extractRawText: jest.fn().mockResolvedValue({
      value: 'mocked docx text with javascript python docker aws react education experience skills projects email: test@example.com phone: 123-456-7890 link: http://github.com/test achievements: improved latency by 30% led managed designed'
    })
  };
});

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const ATSResume = require('../src/models/ATSResume');
const ATSJobDescription = require('../src/models/ATSJobDescription');
const ATSReport = require('../src/models/ATSReport');
const { MONGO_URI } = require('../src/config/env');

describe('ATS Resume Intelligence Engine API Integration Tests', () => {
  let dbConnection;
  let testUser;
  let otherUser;
  let tokenUser;
  let tokenOtherUser;
  let createdReportId;

  beforeAll(async () => {
    dbConnection = await mongoose.connect(MONGO_URI);
    
    // Clear collections
    await User.deleteMany({});
    await ATSResume.deleteMany({});
    await ATSJobDescription.deleteMany({});
    await ATSReport.deleteMany({});

    // Create test user
    testUser = await User.create({
      name: 'ATS User',
      email: 'atsuser@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    otherUser = await User.create({
      name: 'Other User',
      email: 'otheruser@test.com',
      password: 'password123',
      role: 'user',
      isActive: true
    });

    // Login users to get tokens
    const loginUser = await request(app)
      .post('/api/auth/login')
      .send({ email: 'atsuser@test.com', password: 'password123' });
    tokenUser = loginUser.body.accessToken;

    const loginOther = await request(app)
      .post('/api/auth/login')
      .send({ email: 'otheruser@test.com', password: 'password123' });
    tokenOtherUser = loginOther.body.accessToken;
  });

  afterAll(async () => {
    await User.deleteMany({});
    await ATSResume.deleteMany({});
    await ATSJobDescription.deleteMany({});
    await ATSReport.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/ats/analyze', () => {
    it('should successfully analyze a resume against a pasted job description (TXT)', async () => {
      const res = await request(app)
        .post('/api/ats/analyze')
        .set('Authorization', `Bearer ${tokenUser}`)
        .field('jdTitle', 'Frontend Engineer')
        .field('jdText', 'We need a Frontend Engineer with React, Javascript, and Tailwind. Must have projects and experience.')
        .attach('resumeFile', Buffer.from('Resume text contents for plain text matching'), 'resume.txt');

      expect(res.status).toBe(201);
      expect(res.body.reportId).toBeDefined();
      expect(res.body.scores).toBeDefined();
      expect(res.body.scores.consensusScore).toBeGreaterThanOrEqual(0);
      expect(res.body.scores.consensusScore).toBeLessThanOrEqual(100);
      expect(res.body.scores.atsCompatibilityScore).toBeDefined();
      expect(res.body.scores.careerProgressionScore).toBeDefined();
      expect(res.body.scores.jdCoverageScore).toBeDefined();
      expect(res.body.scores.responsibilityCoverage).toBeDefined();
      expect(res.body.analysis.recruiterConfidence).toBeDefined();
      expect(res.body.analysis.benchmarkReliability).toBeDefined();
      expect(res.body.analysis.criticalSkills).toBeDefined();
      expect(res.body.analysis.careerLevel).toBeDefined();
      expect(res.body.analysis.compatibilityIssues).toBeDefined();
      expect(res.body.analysis.careerProgression).toBeDefined();
      expect(res.body.analysis.resumeProgress).toBeDefined();
      expect(res.body.reportMarkdown).toBeDefined();
      
      // Store report ID for subsequent tests
      createdReportId = res.body.reportId;
    });

    it('should successfully analyze a resume (PDF) with mocked pdf-parse', async () => {
      const res = await request(app)
        .post('/api/ats/analyze')
        .set('Authorization', `Bearer ${tokenUser}`)
        .field('jdTitle', 'Backend Engineer')
        .field('jdText', 'We need a Backend Engineer with Python, Javascript, Docker, AWS, and React.')
        .attach('resumeFile', Buffer.from('fake pdf data'), 'resume.pdf');

      expect(res.status).toBe(201);
      expect(res.body.reportId).toBeDefined();
      expect(res.body.scores.consensusScore).toBeGreaterThanOrEqual(50); // should be high due to mock match
    });

    it('should successfully analyze a resume (DOCX) with mocked mammoth', async () => {
      const res = await request(app)
        .post('/api/ats/analyze')
        .set('Authorization', `Bearer ${tokenUser}`)
        .field('jdTitle', 'Full Stack Engineer')
        .field('jdText', 'We need a Developer with Python, React, and Node.js')
        .attach('resumeFile', Buffer.from('fake docx data'), 'resume.docx');

      expect(res.status).toBe(201);
      expect(res.body.reportId).toBeDefined();
    });

    it('should fail if resume file is missing', async () => {
      const res = await request(app)
        .post('/api/ats/analyze')
        .set('Authorization', `Bearer ${tokenUser}`)
        .field('jdTitle', 'No Resume Job')
        .field('jdText', 'Some job text');

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/resume file is required/i);
    });

    it('should fail if job description text and file are both missing', async () => {
      const res = await request(app)
        .post('/api/ats/analyze')
        .set('Authorization', `Bearer ${tokenUser}`)
        .attach('resumeFile', Buffer.from('Resume Text'), 'resume.txt');

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/job description text or file is required/i);
    });
  });

  describe('GET /api/ats/reports', () => {
    it('should retrieve my ATS reports list', async () => {
      const res = await request(app)
        .get('/api/ats/reports')
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.reports)).toBe(true);
      expect(res.body.reports.length).toBeGreaterThanOrEqual(1);
      expect(res.body.reports[0].resumeId).toBeDefined();
      expect(res.body.reports[0].jobDescriptionId).toBeDefined();
    });
  });

  describe('GET /api/ats/reports/:id', () => {
    it('should retrieve a specific ATS report', async () => {
      const res = await request(app)
        .get(`/api/ats/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);
      expect(res.body.report).toBeDefined();
      expect(res.body.report._id).toBe(createdReportId);
      expect(res.body.report.reportMarkdown).toBeDefined();
    });

    it('should block retrieval by other users', async () => {
      const res = await request(app)
        .get(`/api/ats/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenOtherUser}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access denied/i);
    });

    it('should return 404 for invalid report IDs', async () => {
      const invalidId = new mongoose.Types.ObjectId();
      const res = await request(app)
        .get(`/api/ats/reports/${invalidId}`)
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/report not found/i);
    });
  });

  describe('DELETE /api/ats/reports/:id', () => {
    it('should block deletion by other users', async () => {
      const res = await request(app)
        .delete(`/api/ats/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenOtherUser}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access denied/i);
    });

    it('should successfully delete an ATS report', async () => {
      const res = await request(app)
        .delete(`/api/ats/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/ats report deleted/i);

      // Verify it's gone
      const verifyRes = await request(app)
        .get(`/api/ats/reports/${createdReportId}`)
        .set('Authorization', `Bearer ${tokenUser}`);
      expect(verifyRes.status).toBe(404);
    });
  });

  describe('ATS Engine Helper Unit Tests', () => {
    const {
      extractLocalEntities,
      parseExperienceYears,
      extractSections,
      evaluateKeywordMatch,
      extractActionVerbs,
      parseContactInfo
    } = require('../src/controllers/atsController');

    describe('Skill Extraction & Alias Normalization', () => {
      it('should extract canonical skills and normalize aliases correctly', () => {
        const skillLookup = new Map([
          ['react', 'react'],
          ['react.js', 'react'],
          ['reactjs', 'react'],
          ['node.js', 'node'],
          ['nodejs', 'node'],
          ['javascript', 'javascript'],
          ['js', 'javascript']
        ]);

        const text = 'I am experienced in React.js, nodejs, and js development.';
        const result = extractLocalEntities(text, skillLookup);

        expect(result).toContain('react');
        expect(result).toContain('node');
        expect(result).toContain('javascript');
        expect(result.length).toBe(3);
      });

      it('should respect boundary safety for single-letter and symbol skills', () => {
        const skillLookup = new Map([
          ['c++', 'c++'],
          ['c', 'c'],
          ['c#', 'c#']
        ]);

        const text = 'We need a C++ engineer with experience in C#.';
        const result = extractLocalEntities(text, skillLookup);

        expect(result).toContain('c++');
        expect(result).toContain('c#');
        expect(result).not.toContain('c'); // should not match 'c' standalone because of word boundaries
      });
    });

    describe('Experience Heading & Date Range Parsing', () => {
      it('should extract text by experience sections and count years of experience', () => {
        const text = `
Resume Summary:
Software developer with passion.

EXPERIENCE
Company A: 2018 - 2021
Company B: 2021 - Present

EDUCATION
University: 2014 - 2018

PROJECTS
Side Project: 2020 - 2022
`;
        const sections = extractSections(text);
        expect(sections['EXPERIENCE']).toBeDefined();
        expect(sections['EDUCATION']).toBeDefined();
        expect(sections['PROJECTS']).toBeDefined();

        const years = parseExperienceYears(sections);
        const currentYear = new Date().getFullYear();
        const expectedYears = (2021 - 2018) + (currentYear - 2021);
        expect(years).toBe(expectedYears);
      });

      it('should handle overlapping date ranges and avoid double counting', () => {
        const sections = {
          'EXPERIENCE': 'Job 1: 2015 - 2020\nJob 2 (concurrent): 2017 - 2019'
        };
        const years = parseExperienceYears(sections);
        expect(years).toBe(5); // 2020 - 2015
      });
    });

    describe('Contact Information & Action Verbs Parsing', () => {
      it('should extract contact details correctly', () => {
        const text = 'John Doe. Email: john.doe@example.com, Phone: (123) 456-7890. github.com/johndoe linkedin.com/in/johndoe';
        const contact = parseContactInfo(text);

        expect(contact.email).toBe('john.doe@example.com');
        expect(contact.phone).toBe('(123) 456-7890');
        expect(contact.linkedin).toBe('linkedin.com/in/johndoe');
        expect(contact.github).toBe('github.com/johndoe');
      });

      it('should identify action verbs and match keyword overlap', () => {
        const text = 'We built a dashboard, optimized the performance, and improved latency.';
        const verbs = extractActionVerbs(text);

        expect(verbs).toContain('built');
        expect(verbs).toContain('optimized');
        expect(verbs).toContain('improved');

        const jdKeywords = ['built', 'marketed', 'optimized'];
        const score = evaluateKeywordMatch(text, jdKeywords);
        expect(score).toBe(67); // built, optimized matched (2/3)
      });
    });

    describe('ATS V2.1 Core Helpers', () => {
      const {
        auditAtsCompatibilityAndRisk,
        detectCareerLevel,
        analyzeCareerProgression
      } = require('../src/controllers/atsController');

      it('should audit compatibility correctly', () => {
        const text = 'John Doe. No contact info here.';
        const audit = auditAtsCompatibilityAndRisk(Buffer.from(text), 'text/plain', 'resume.txt', text, false);
        expect(audit.atsCompatibilityScore).toBeLessThan(100);
        expect(audit.compatibilityIssues.length).toBeGreaterThan(0);
      });

      it('should detect career levels based on years and keywords', () => {
        expect(detectCareerLevel(1, 'some text', 'Software Engineer')).toBe('Junior');
        expect(detectCareerLevel(6, 'some text', 'Senior Developer')).toBe('Senior');
        expect(detectCareerLevel(12, 'vp engineering', 'Vice President')).toBe('Director');
      });

      it('should evaluate career progression and flag demotions', () => {
        const goodProgression = '2018: Intern\n2020: Developer\n2023: Senior Developer';
        const goodResult = analyzeCareerProgression(goodProgression);
        expect(goodResult.careerProgressionScore).toBe(100);

        const demotionProgression = '2018: Senior Developer\n2022: Intern';
        const demotionResult = analyzeCareerProgression(demotionProgression);
        expect(demotionResult.careerProgressionScore).toBeLessThan(100);
      });
    });
  });
});
