'use strict';

const mongoose = require('mongoose');

const plagiarismReportSchema = new mongoose.Schema(
  {
    documentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'PlagiarismDocument',
      required: true,
    },
    scores: {
      plagiarismIndex: { type: Number, required: true }, // Weighted Consensus (0-100)
      exactMatchScore: { type: Number, required: true },
      sequenceScore: { type: Number, required: true },
      paraphraseScore: { type: Number, required: true },
      semanticScore: { type: Number, required: true },
      aiRewriteScore: { type: Number, required: true },
      semanticSimilarity: { type: Number, default: 0 },
      paraphraseDetection: { type: Number, default: 0 },
      contextPreservation: { type: Number, default: 0 },
    },
    matches: [
      {
        matchedDocumentId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'PlagiarismDocument',
        },
        matchedTitle: { type: String, required: true },
        similarityScore: { type: Number, required: true }, // 0-100
        matchingTextSegments: [
          {
            originalSegment: { type: String, required: true },
            sourceSegment: { type: String, required: true },
            matchType: {
              type: String,
              enum: ['exact', 'near-match', 'paraphrased', 'semantic', 'ai-rewrite'],
              required: true,
            },
          },
        ],
      },
    ],
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

module.exports = mongoose.models.PlagiarismReport || mongoose.model('PlagiarismReport', plagiarismReportSchema);
