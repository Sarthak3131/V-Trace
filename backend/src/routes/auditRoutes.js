'use strict';

const express = require('express');
const { protect, restrictTo } = require('../middleware/auth');
const { getAuditLogs, verifyAuditChain, getEntityHistory, getSystemMetrics } = require('../controllers/auditController');

const router = express.Router();

// Apply auth protection middleware to all audit routes
router.use(protect);

// Retrieve all audit logs (any logged in user/investigator can inspect events for audit transparency)
router.get('/', getAuditLogs);

// Perform cryptographic integrity verify (restricted to admins and moderators)
router.get('/verify', restrictTo('admin', 'moderator'), verifyAuditChain);

// Retrieve system health and metrics data (restricted to admins and moderators)
router.get('/metrics', restrictTo('admin', 'moderator'), getSystemMetrics);

// Retrieve custody event timeline for a specific content or case entity
router.get('/entity/:entityType/:entityId', getEntityHistory);

module.exports = router;
