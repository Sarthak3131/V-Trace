'use strict';

const mongoose = require('mongoose');

const ALLOWED_FINDINGS = [
  'none',
  'software-edit',
  'revision-anomaly',
  'script-detected',
  'atypical-entropy',
  'metadata-missing'
];

const aiAnalysisResultSchema = new mongoose.Schema(
  {
    contentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Content',
      required: true,
      unique: true,
    },
    status: {
      type: String,
      enum: ['pending', 'completed', 'failed'],
      default: 'pending',
    },
    metadataRiskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    integrityVerificationScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
    },
    verificationConfidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
    },
    metadataFindings: {
      type: String,
      enum: ALLOWED_FINDINGS,
      default: 'none',
    },
    analysisLogs: {
      type: [String],
      default: [],
    },
    forensicReport: {
      type: String,
      default: '',
    },
    processedAt: {
      type: Date,
    },
    errorMessage: {
      type: String,
    },
  },
  { timestamps: true }
);

aiAnalysisResultSchema.index({ status: 1 });

module.exports = mongoose.models.AIAnalysisResult || mongoose.model('AIAnalysisResult', aiAnalysisResultSchema);
