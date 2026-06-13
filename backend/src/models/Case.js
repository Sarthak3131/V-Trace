'use strict';

const mongoose = require('mongoose');

const ALLOWED_STATUSES = ['open', 'in-progress', 'resolved', 'closed'];
const ALLOWED_SEVERITIES = ['low', 'medium', 'high', 'critical'];

const caseSchema = new mongoose.Schema(
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
    status: {
      type: String,
      enum: ALLOWED_STATUSES,
      default: 'open',
    },
    severity: {
      type: String,
      enum: ALLOWED_SEVERITIES,
      default: 'medium',
    },
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    evidence: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Content',
      },
    ],
    notes: [
      {
        text: {
          type: String,
          required: true,
          trim: true,
          maxlength: 2000,
        },
        createdBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
          required: true,
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    history: [
      {
        action: {
          type: String,
          required: true,
        },
        details: {
          type: String,
        },
        performedBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
          required: true,
        },
        performedAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  {
    timestamps: true,
  }
);

// Indexes for query performance
caseSchema.index({ status: 1 });
caseSchema.index({ severity: 1 });
caseSchema.index({ assignedTo: 1 });
caseSchema.index({ createdBy: 1 });

module.exports = mongoose.model('Case', caseSchema);
