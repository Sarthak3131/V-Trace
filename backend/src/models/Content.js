'use strict';

const mongoose = require('mongoose');

const ALLOWED_CONTENT_TYPES = ['text', 'image', 'document', 'video', 'audio'];
const ALLOWED_STATUS = ['pending', 'verified', 'flagged', 'rejected'];

const contentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxlength: 200,
    },
    description: {
      type: String,
      trim: true,
      maxlength: 1000,
    },
    contentType: {
      type: String,
      required: true,
      enum: ALLOWED_CONTENT_TYPES,
      default: 'text',
    },
    originalHash: {
      type: String,
      required: true,
      trim: true,
    },
    merkleRoot: {
      type: String,
      trim: true,
    },
    chunkHashes: {
      type: [String],
      default: [],
    },
    fileSize: {
      type: Number,
      min: 0,
    },
    mimeType: {
      type: String,
      trim: true,
    },
    status: {
      type: String,
      enum: ALLOWED_STATUS,
      default: 'pending',
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    tags: {
      type: [
        {
          type: String,
          trim: true,
          maxlength: 50,
        },
      ],
      default: [],
      validate: {
        validator(value) {
          return !value || value.length <= 10;
        },
        message: 'Tags can contain at most 10 items',
      },
    },
    isPublic: {
      type: Boolean,
      default: false,
    },
    verifiedAt: {
      type: Date,
    },
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    parentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Content',
      default: null,
    },
    derivationType: {
      type: String,
      enum: ['original', 'copy', 'edit', 'ai-modification', 'splice'],
      default: 'original',
    },
    authenticityScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
    },
    provenanceScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 100,
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
  },
  { timestamps: true }
);

contentSchema.index({ owner: 1 });
contentSchema.index({ status: 1 });
contentSchema.index({ originalHash: 1 });
contentSchema.index({ owner: 1, status: 1 });
contentSchema.index({ createdAt: -1 });
contentSchema.index({ parentId: 1 });

contentSchema.pre('save', function normalizeTags() {
  if (Array.isArray(this.tags)) {
    this.tags = [...new Set(this.tags.map((tag) => String(tag).trim().toLowerCase()).filter(Boolean))];
  }
});

contentSchema.virtual('isVerified').get(function isVerified() {
  return this.status === 'verified';
});

module.exports = mongoose.models.Content || mongoose.model('Content', contentSchema);
