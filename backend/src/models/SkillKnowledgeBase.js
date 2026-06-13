'use strict';

const mongoose = require('mongoose');

const ALLOWED_CATEGORIES = [
  'frontend',
  'backend',
  'database',
  'cloud',
  'devops',
  'security',
  'ai/ml',
  'data science',
  'mobile',
  'testing',
  'ui/ux',
  'management',
  'marketing',
  'sales',
  'finance',
  'product',
  'hr'
];

const skillKnowledgeBaseSchema = new mongoose.Schema(
  {
    canonicalName: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    aliases: {
      type: [String],
      default: [],
      lowercase: true,
      trim: true,
    },
    category: {
      type: String,
      required: true,
      enum: ALLOWED_CATEGORIES,
      lowercase: true,
      trim: true,
    },
    popularityScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 50,
    },
    relatedSkills: {
      type: [String],
      default: [],
      lowercase: true,
      trim: true,
    },
  },
  { timestamps: true }
);

skillKnowledgeBaseSchema.index({ aliases: 1 });
skillKnowledgeBaseSchema.index({ category: 1 });

module.exports = mongoose.models.SkillKnowledgeBase || mongoose.model('SkillKnowledgeBase', skillKnowledgeBaseSchema);
