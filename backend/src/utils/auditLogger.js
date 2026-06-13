'use strict';

const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');

let pendingLogPromise = Promise.resolve();

/**
 * Cryptographically logs a system action into the AuditLog ledger.
 * Serializes insertions using a promise chain to prevent hash race conditions.
 */
async function logEvent({ action, entityType, entityId, performedBy, details }) {
  return new Promise((resolve, reject) => {
    pendingLogPromise = pendingLogPromise
      .then(async () => {
        try {
          // Find the latest log document based on timestamp and ID to ensure ordering
          const lastLog = await AuditLog.findOne().sort({ timestamp: -1, _id: -1 });
          const previousLogHash = lastLog ? lastLog.hash : 'GENESIS_HASH_SEED_V_TRACE';

          const timestamp = new Date();
          const detailsStr = details ? JSON.stringify(details) : '{}';

          // Format: action|entityType|entityId|performedBy|details|timestamp|previousLogHash
          const serialized = `${action}|${entityType}|${entityId ? entityId.toString() : ''}|${
            performedBy ? performedBy.toString() : ''
          }|${detailsStr}|${timestamp.toISOString()}|${previousLogHash}`;

          const hash = crypto.createHash('sha256').update(serialized).digest('hex');

          const log = await AuditLog.create({
            action,
            entityType,
            entityId,
            performedBy,
            details: details || {},
            timestamp,
            previousLogHash,
            hash,
          });

          resolve(log);
        } catch (error) {
          reject(error);
        }
      })
      .catch((error) => {
        // Log the internal error but let the promise chain continue
        console.error('Audit logger failed to record event:', error);
        reject(error);
      });
  });
}

module.exports = {
  logEvent,
};
