'use strict';

const mongoose = require('mongoose');

const plagiarismDocumentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    fileName: {
      type: String,
      required: true,
      trim: true,
    },
    rawText: {
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

module.exports = mongoose.models.PlagiarismDocument || mongoose.model('PlagiarismDocument', plagiarismDocumentSchema);
