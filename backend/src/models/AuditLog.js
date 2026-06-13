'use strict';

const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
  {
    action: {
      type: String,
      required: true,
      index: true,
    },
    entityType: {
      type: String,
      required: true,
      enum: ['Content', 'Case', 'User'],
      index: true,
    },
    entityId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    timestamp: {
      type: Date,
      required: true,
      default: Date.now,
      index: true,
    },
    previousLogHash: {
      type: String,
      required: true,
    },
    hash: {
      type: String,
      required: true,
      unique: true,
    },
  },
  { timestamps: false }
);

module.exports = mongoose.models.AuditLog || mongoose.model('AuditLog', auditLogSchema);
