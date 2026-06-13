'use strict';

const mongoose = require('mongoose');

const atsResumeSchema = new mongoose.Schema(
  {
    fileName: {
      type: String,
      required: true,
      trim: true,
    },
    rawText: {
      type: String,
      required: true,
    },
    metadata: {
      email: { type: String, trim: true },
      phone: { type: String, trim: true },
      links: { type: [String], default: [] },
      sectionsFound: { type: [String], default: [] },
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.ATSResume || mongoose.model('ATSResume', atsResumeSchema);
