'use strict';

const mongoose = require('mongoose');

const atsJobDescriptionSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    rawText: {
      type: String,
      required: true,
    },
    skills: {
      type: [String],
      default: [],
    },
    keywords: {
      type: [String],
      default: [],
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.ATSJobDescription || mongoose.model('ATSJobDescription', atsJobDescriptionSchema);
