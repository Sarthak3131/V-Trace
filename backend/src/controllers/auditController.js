'use strict';

const crypto = require('crypto');
const mongoose = require('mongoose');
const AuditLog = require('../models/AuditLog');
const User = require('../models/User');
const Content = require('../models/Content');
const Case = require('../models/Case');
const { getMetricsData } = require('../middleware/metrics');

function parsePagination(query) {
  const page = Math.max(parseInt(query.page, 10) || 1, 1);
  const requestedLimit = parseInt(query.limit, 10) || 20;
  const limit = Math.min(Math.max(requestedLimit, 1), 100);
  const skip = (page - 1) * limit;

  return { page, limit, skip };
}

// Get paginated list of audit logs
async function getAuditLogs(req, res, next) {
  try {
    const { page, limit, skip } = parsePagination(req.query);
    const filter = {};

    if (req.query.action) {
      filter.action = String(req.query.action);
    }
    if (req.query.entityType) {
      filter.entityType = String(req.query.entityType);
    }
    if (req.query.entityId) {
      if (mongoose.Types.ObjectId.isValid(req.query.entityId)) {
        filter.entityId = req.query.entityId;
      } else {
        return res.status(400).json({ error: 'Invalid entityId format' });
      }
    }
    if (req.query.performedBy) {
      if (mongoose.Types.ObjectId.isValid(req.query.performedBy)) {
        filter.performedBy = req.query.performedBy;
      } else {
        return res.status(400).json({ error: 'Invalid performedBy user ID format' });
      }
    }

    const [logs, total] = await Promise.all([
      AuditLog.find(filter)
        .populate('performedBy', 'name email role')
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit),
      AuditLog.countDocuments(filter),
    ]);

    return res.status(200).json({
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit) || 1,
      },
    });
  } catch (error) {
    return next(error);
  }
}

// Cryptographically verify integrity of the entire AuditLog chain
async function verifyAuditChain(req, res, next) {
  try {
    let currentPrevHash = 'GENESIS_HASH_SEED_V_TRACE';
    const compromised = [];

    // Use a cursor to process logs sequentially, maintaining O(1) memory usage
    const cursor = AuditLog.find().sort({ timestamp: 1, _id: 1 }).cursor();

    for (let log = await cursor.next(); log != null; log = await cursor.next()) {
      const detailsStr = log.details ? JSON.stringify(log.details) : '{}';

      // Format must match serialization inside auditLogger.js exactly:
      // action|entityType|entityId|performedBy|details|timestamp|previousLogHash
      const serialized = `${log.action}|${log.entityType}|${log.entityId ? log.entityId.toString() : ''}|${
        log.performedBy ? log.performedBy.toString() : ''
      }|${detailsStr}|${log.timestamp.toISOString()}|${currentPrevHash}`;

      const expectedHash = crypto.createHash('sha256').update(serialized).digest('hex');

      if (log.hash !== expectedHash || log.previousLogHash !== currentPrevHash) {
        compromised.push({
          _id: log._id,
          action: log.action,
          entityType: log.entityType,
          entityId: log.entityId,
          timestamp: log.timestamp,
          expectedHash,
          actualHash: log.hash,
          expectedPrevHash: currentPrevHash,
          actualPrevHash: log.previousLogHash,
        });
      }

      currentPrevHash = log.hash;
    }

    return res.status(200).json({
      verified: compromised.length === 0,
      compromisedLogsCount: compromised.length,
      compromisedLogs: compromised,
    });
  } catch (error) {
    return next(error);
  }
}

// Get event history timeline for a specific entity (e.g. Content or Case)
async function getEntityHistory(req, res, next) {
  try {
    const { entityType, entityId } = req.params;

    if (!entityType || !entityId) {
      return res.status(400).json({ error: 'entityType and entityId are required parameters' });
    }

    if (!mongoose.Types.ObjectId.isValid(entityId)) {
      return res.status(400).json({ error: 'Invalid entityId format' });
    }

    const history = await AuditLog.find({
      entityType,
      entityId,
    })
      .populate('performedBy', 'name email role')
      .sort({ timestamp: -1 });

    return res.status(200).json({ history });
  } catch (error) {
    return next(error);
  }
}

// Get platform system metrics
async function getSystemMetrics(req, res, next) {
  try {
    const [totalUsers, totalContents, totalCases, totalAuditLogs] = await Promise.all([
      User.countDocuments(),
      Content.countDocuments(),
      Case.countDocuments(),
      AuditLog.countDocuments(),
    ]);

    const trafficMetrics = getMetricsData();

    return res.status(200).json({
      dbStats: {
        totalUsers,
        totalContents,
        totalCases,
        totalAuditLogs,
      },
      trafficStats: trafficMetrics,
    });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  getAuditLogs,
  verifyAuditChain,
  getEntityHistory,
  getSystemMetrics,
};
