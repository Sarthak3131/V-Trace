'use strict';

const crypto = require('crypto');
const Case = require('../models/Case');
const Content = require('../models/Content');
const AIAnalysisResult = require('../models/AIAnalysisResult');
const AuditLog = require('../models/AuditLog');
const ATSReport = require('../models/ATSReport');
const PlagiarismReport = require('../models/PlagiarismReport');

async function getDashboardStats(req, res, next) {
  try {
    // 1. Basic Counts
    const [
      totalCases, 
      activeCases, 
      totalContent, 
      verifiedContent, 
      flaggedContent, 
      rejectedContent,
      atsCount,
      plagCount
    ] = await Promise.all([
      Case.countDocuments(),
      Case.countDocuments({ status: 'in-progress' }),
      Content.countDocuments(),
      Content.countDocuments({ status: 'verified' }),
      Content.countDocuments({ status: 'flagged' }),
      Content.countDocuments({ status: 'rejected' }),
      ATSReport.countDocuments({ owner: req.user.userId }),
      PlagiarismReport.countDocuments({ owner: req.user.userId }),
    ]);

    // 2. Threat Score: average metadataRiskScore of analyzed contents
    const analyzedContents = await Content.find({ status: { $ne: 'pending' } }, 'metadataRiskScore');
    let threatScore = 0;
    if (analyzedContents.length > 0) {
      const totalProb = analyzedContents.reduce((sum, item) => sum + (item.metadataRiskScore || 0), 0);
      threatScore = Math.round(totalProb / analyzedContents.length);
    }

    // 3. Verification Success Rate: verified / (verified + flagged + rejected) * 100
    const totalAnalyzed = verifiedContent + flaggedContent + rejectedContent;
    const verificationRate = totalAnalyzed > 0 ? Math.round((verifiedContent / totalAnalyzed) * 100) : 100;

    // 4. Ledger Integrity: verify cryptographically
    let currentPrevHash = 'GENESIS_HASH_SEED_V_TRACE';
    let totalLogs = 0;
    let validLogsCount = 0;

    const cursor = AuditLog.find().sort({ timestamp: 1, _id: 1 }).cursor();
    for (let log = await cursor.next(); log != null; log = await cursor.next()) {
      totalLogs++;
      const detailsStr = log.details ? JSON.stringify(log.details) : '{}';
      
      const serialized = `${log.action}|${log.entityType}|${log.entityId ? log.entityId.toString() : ''}|${
        log.performedBy ? log.performedBy.toString() : ''
      }|${detailsStr}|${log.timestamp.toISOString()}|${currentPrevHash}`;

      const expectedHash = crypto.createHash('sha256').update(serialized).digest('hex');

      if (log.hash === expectedHash && log.previousLogHash === currentPrevHash) {
        validLogsCount++;
      }
      currentPrevHash = log.hash;
    }

    const ledgerIntegrity = totalLogs > 0 ? parseFloat(((validLogsCount / totalLogs) * 100).toFixed(1)) : 100.0;

    // 5. Ingest Rate: global events per day over the last 7 days
    const daysOfWeek = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const ingestRateRaw = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const startOfDay = new Date(d);
      startOfDay.setHours(0, 0, 0, 0);
      const endOfDay = new Date(d);
      endOfDay.setHours(23, 59, 59, 999);

      const count = await Content.countDocuments({
        createdAt: { $gte: startOfDay, $lte: endOfDay }
      });
      
      ingestRateRaw.push({
        day: daysOfWeek[d.getDay()],
        count
      });
    }

    const maxCount = Math.max(...ingestRateRaw.map(r => r.count), 1);
    const ingestRate = ingestRateRaw.map(r => ({
      day: r.day,
      count: r.count,
      val: Math.round((r.count / maxCount) * 80) + 15 // Beautifully scale between 15-95% for layout consistency
    }));

    // 6. Evidence Distribution (format distribution)
    const types = [
      { key: 'image', label: 'Images', color: 'bg-emerald-400' },
      { key: 'video', label: 'Video', color: 'bg-cyan-400' },
      { key: 'audio', label: 'Audio', color: 'bg-indigo-400' },
      { key: 'document', label: 'Documents', color: 'bg-purple-400' },
      { key: 'text', label: 'Text Files', color: 'bg-pink-400' }
    ];

    const formatDistribution = [];
    for (const type of types) {
      const count = await Content.countDocuments({ contentType: type.key });
      const pct = totalContent > 0 ? Math.round((count / totalContent) * 100) : 0;
      formatDistribution.push({
        type: type.label,
        count,
        pct,
        color: type.color
      });
    }

    // 7. Security & Integrity Insights: dynamic alert feed
    const results = await AIAnalysisResult.find({ status: 'completed' })
      .populate('contentId')
      .sort({ processedAt: -1 })
      .limit(5);

    const aiInsights = results
      .filter(r => r.contentId)
      .map(r => {
        const content = r.contentId;
        const isHighRisk = r.metadataRiskScore >= 75;
        const isMedRisk = r.metadataRiskScore >= 40 && r.metadataRiskScore < 75;
        
        let severity = 'low';
        if (isHighRisk) severity = 'high';
        else if (isMedRisk) severity = 'medium';

        let title = 'Asset Verification Success';
        let desc = `Verification completed for "${content.title}". Verdict: ${content.status.toUpperCase()} (Integrity Score: ${content.integrityVerificationScore}%).`;
        
        if (content.status === 'flagged') {
          title = 'Metadata Alteration Alert';
          desc = `Local anomalies detected in "${content.title}". Risk score: ${r.metadataRiskScore}% (${r.metadataFindings}).`;
        } else if (content.status === 'rejected') {
          title = 'Asset Integrity Failed';
          desc = `Media block "${content.title}" rejected due to failed cryptographic signatures.`;
        }

        const diffMs = Date.now() - new Date(r.processedAt).getTime();
        const diffMins = Math.floor(diffMs / (60 * 1000));
        let timeStr = 'Just now';
        if (diffMins > 0) {
          if (diffMins < 60) {
            timeStr = `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
          } else {
            const diffHours = Math.floor(diffMins / 60);
            if (diffHours < 24) {
              timeStr = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
            } else {
              timeStr = `${Math.floor(diffHours / 24)} day${Math.floor(diffHours / 24) > 1 ? 's' : ''} ago`;
            }
          }
        }

        return {
          id: `insight_${r._id}`,
          title,
          desc,
          severity,
          time: timeStr
        };
      });

    return res.status(200).json({
      totalCases,
      activeCases,
      totalContent,
      threatScore,
      verificationRate,
      ledgerIntegrity,
      ingestRate,
      formatDistribution,
      aiInsights,
      atsCount,
      plagCount
    });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  getDashboardStats
};
