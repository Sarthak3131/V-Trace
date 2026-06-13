'use strict';

const mongoose = require('mongoose');

const atsReportSchema = new mongoose.Schema(
  {
    resumeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ATSResume',
      required: true,
    },
    jobDescriptionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ATSJobDescription',
      required: true,
    },
    cacheKey: {
      type: String,
      index: true,
    },
    scores: {
      consensusScore: { type: Number, required: true }, // final ATS score
      keywordScore: { type: Number, required: true }, // keywordMatchPercent
      skillScore: { type: Number, required: true }, // weightedSkillCoverage
      qualityScore: { type: Number, required: true }, // structureScore
      recruiterScore: { type: Number, required: true }, // recruiterScore
      semanticScore: { type: Number, default: 0 }, // semanticScore
      experienceScore: { type: Number, default: 0 }, // experienceAlignment
      atsRiskScore: { type: Number, default: 0 }, // risk score
      interviewProbability: { type: Number, default: 0 }, // probability score
      atsCompatibilityScore: { type: Number, default: 100 },
      careerProgressionScore: { type: Number, default: 100 },
      responsibilityCoverage: { type: Number, default: 0 },
      jdCoverageScore: { type: Number, default: 0 }
    },
    analysis: {
      role: { type: String, default: '' },
      candidateType: { type: String, enum: ['fresher', 'experienced'], default: 'fresher' },
      yearsOfExperience: { type: Number, default: 0 },
      careerLevel: { type: String, default: 'Junior' },
      resumeSkills: { type: [String], default: [] },
      jdSkills: { type: [String], default: [] },
      matchedSkills: { type: [String], default: [] },
      missingSkills: { type: [String], default: [] },
      extraSkills: { type: [String], default: [] },
      matchedKeywords: { type: [String], default: [] },
      missingKeywords: { type: [String], default: [] },
      requiredSkills: { type: [String], default: [] },
      preferredSkills: { type: [String], default: [] },
      learningRoadmap: {
        priority1: { type: [String], default: [] },
        priority2: { type: [String], default: [] },
        priority3: { type: [String], default: [] },
      },
      benchmarkRank: { type: String, default: 'Below Average' },
      strengths: { type: [String], default: [] },
      weaknesses: { type: [String], default: [] },
      structureIssues: { type: [String], default: [] },
      compatibilityIssues: { type: [String], default: [] },
      compatibilityWarnings: { type: [String], default: [] },
      riskFactors: { type: [String], default: [] },
      careerProgression: { type: String, default: '' },
      resumeProgress: {
        previousScore: { type: Number, default: 0 },
        currentScore: { type: Number, default: 0 },
        improvement: { type: Number, default: 0 },
        newSkillsAdded: { type: [String], default: [] },
        resolvedIssues: { type: [String], default: [] },
        newIssues: { type: [String], default: [] }
      },
      recommendations: { type: [String], default: [] },
      recruiterRecommendation: { type: String, default: 'Consider' },
      semanticReasoning: { type: String, default: '' },
      achievementsCount: { type: Number, default: 0 },
      actionVerbsUsed: { type: [String], default: [] },

      matchedTechSkills: { type: [String], default: [] },
      missingTechSkills: { type: [String], default: [] },
      matchedRespKeywords: { type: [String], default: [] },
      missingRespKeywords: { type: [String], default: [] },
      matchedVerbs: { type: [String], default: [] },
      missingVerbs: { type: [String], default: [] },
      matchedResponsibilities: { type: [String], default: [] },
      missingResponsibilities: { type: [String], default: [] },
      roleDatasetSize: { type: Number, default: 0 },
      rankPosition: { type: Number, default: 1 },
      benchmarkMethod: { type: String, default: 'Percentile' },
      semanticEngine: { type: String, default: 'Gemini 2.5 Flash' },
      recruiterConfidence: { type: Number, default: 100 },
      criticalSkills: { type: [String], default: [] },
      benchmarkReliability: { type: String, default: 'Low' }
    },
    reportMarkdown: {
      type: String,
      required: true,
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
  },
  { timestamps: true }
);

atsReportSchema.index({ owner: 1 });

module.exports = mongoose.models.ATSReport || mongoose.model('ATSReport', atsReportSchema);
