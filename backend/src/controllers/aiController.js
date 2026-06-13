'use strict';

const mongoose = require('mongoose');
const Case = require('../models/Case');
const Content = require('../models/Content');
const AIAnalysisResult = require('../models/AIAnalysisResult');
const AuditLog = require('../models/AuditLog');
const ATSReport = require('../models/ATSReport');
const { isProviderConfigured, generateAIResponse, classifyIntent } = require('../utils/aiProvider');
const { MASTER_SYSTEM_PROMPT } = require('../utils/systemPrompt');

const SITE_MAP = {
  "/dashboard": "Investigation dashboard and analytics",
  "/verify": "Verify file authenticity and integrity",
  "/evidence-library": "Browse and manage evidence",
  "/cases": "Create and manage investigations",
  "/resume-intel": "ATS resume analysis engine",
  "/plagiarism-check": "Document plagiarism detection",
  "/activity-history": "Audit trail and activity logs"
};

const ATS_EXPERT_PROMPT = `
[EXPERT MODE: ATS ANALYSIS]
You are acting as the V-Trace ATS Expert.
Provide detailed, recruiter-grade analysis on the candidate's ATS report. Focus on:
- Consensus score, skill match score, and career seniority level.
- Specific missing skills and layout/compatibility warnings (like columns, tables, images).
- Recruiter confidence metrics and benchmark reliability.
- JD coverage (rebalanced match of skills, responsibilities, and experience).
Never give generic ATS advice. Use the exact score percentages and missing skill names from the provided ATS Report details.
`;

const INVESTIGATION_EXPERT_PROMPT = `
[EXPERT MODE: DIGITAL FORENSICS & INVESTIGATION]
You are acting as the V-Trace Forensic Analyst.
Provide analytical, precise, and structured investigation summaries. Focus on:
- Summarizing the case status, severity, notes, and evidence list.
- Explaining evidence verification status, integrity scores, and provenance score.
- Highlighting risk factors (e.g. metadata risk score, authenticity issues, flagged tags).
- Generating timelines or incident reports when requested.
Use actual filename details, hashes, and notes from the case/evidence context.
`;

// Global debug state variable
let lastChatDebugInfo = {
  provider: "Offline Engine",
  intent: "GREETING",
  route: "/dashboard",
  selectedCase: false,
  selectedEvidence: false,
  atsLoaded: false,
  historyMessages: 0,
  responseSource: "offline"
};

function getLastChatDebugInfo() {
  return lastChatDebugInfo;
}

/**
 * Context Ranking Engine: Filters out irrelevant context based on intent.
 */
function rankAndFilterContext(intent, rawContext) {
  let blocks = [];
  blocks.push(`User:\n${rawContext.userContextStr}`);

  if (rawContext.routeContextStr) {
    blocks.push(`Current Route & Site Map:\n${rawContext.routeContextStr}`);
  }

  switch (intent) {
    case 'ATS_ANALYSIS':
      if (rawContext.atsContextStr) {
        blocks.push(`ATS Report Details:\n${rawContext.atsContextStr}`);
      }
      break;

    case 'CASE_ANALYSIS':
      if (rawContext.caseContextStr) {
        blocks.push(`Selected Case Details:\n${rawContext.caseContextStr}`);
      }
      if (rawContext.dashboardContextStr) {
        blocks.push(`Dashboard Metrics:\n${rawContext.dashboardContextStr}`);
      }
      break;

    case 'EVIDENCE_ANALYSIS':
      if (rawContext.evidenceContextStr) {
        blocks.push(`Selected Evidence Details:\n${rawContext.evidenceContextStr}`);
      }
      if (rawContext.caseContextStr) {
        blocks.push(`Associated Case Details:\n${rawContext.caseContextStr}`);
      }
      break;

    case 'DASHBOARD_QUERY':
      if (rawContext.dashboardContextStr) {
        blocks.push(`Dashboard Metrics:\n${rawContext.dashboardContextStr}`);
      }
      if (rawContext.auditContextStr) {
        blocks.push(`Activity Logs:\n${rawContext.auditContextStr}`);
      }
      break;

    case 'REPORT_GENERATION':
      if (rawContext.caseContextStr) {
        blocks.push(`Case Data:\n${rawContext.caseContextStr}`);
      }
      if (rawContext.evidenceContextStr) {
        blocks.push(`Evidence Data:\n${rawContext.evidenceContextStr}`);
      }
      if (rawContext.atsContextStr) {
        blocks.push(`ATS Data:\n${rawContext.atsContextStr}`);
      }
      break;

    case 'NAVIGATION':
    case 'GENERAL_HELP':
    default:
      if (rawContext.dashboardContextStr) {
        blocks.push(`Dashboard Metrics:\n${rawContext.dashboardContextStr}`);
      }
      break;
  }

  return `[PLATFORM CONTEXT]\n${blocks.join('\n\n')}\n[/PLATFORM CONTEXT]`;
}

/**
 * Self-Evaluation Layer: Checks response quality.
 */
function selfEvaluate(reply, intent, userMessage) {
  const replyLower = reply.toLowerCase();
  
  if (reply.trim().length < 40) {
    return false;
  }
  
  if (replyLower.includes("don't have access") || 
      replyLower.includes("cannot access") || 
      replyLower.includes("do not have access") ||
      replyLower.includes("no access") ||
      replyLower.includes("api key") ||
      replyLower.includes("service is currently unavailable") ||
      replyLower.includes("service unavailable")) {
    return false;
  }

  return true;
}

/**
 * Response Quality Guard: Checks for template overrides or short texts.
 */
function evaluateResponseQuality(response, intent) {
  if (response.length < 50) return false;
  
  const upper = response.toUpperCase();
  if (upper.includes('ACTIVE CASES INQUIRY') || 
      upper.includes('NO ACTIVE CASE') || 
      upper.includes('CASE TEMPLATE') || 
      upper.includes('DEFAULT RESPONSE')) {
    return false;
  }
  
  return true;
}

async function handleChat(req, res, next) {
  try {
    const { message, history = [], caseId, evidenceId, currentRoute } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'message is required' });
    }

    // 1. Smart Intent Detection
    const intent = classifyIntent(message, history);

    // 2. Conversation Memory Layer (Resolving entity IDs)
    let activeCaseId = caseId;
    if (!activeCaseId) {
      const latestCase = await Case.findOne({ createdBy: req.user.userId }).sort({ updatedAt: -1 });
      if (latestCase) activeCaseId = latestCase._id;
    }

    let activeEvidenceId = evidenceId;
    if (!activeEvidenceId) {
      if (activeCaseId) {
        const kase = await Case.findById(activeCaseId);
        if (kase && kase.evidence && kase.evidence.length > 0) {
          activeEvidenceId = kase.evidence[0];
        }
      }
      if (!activeEvidenceId) {
        const latestEvidence = await Content.findOne({ owner: req.user.userId }).sort({ createdAt: -1 });
        if (latestEvidence) activeEvidenceId = latestEvidence._id;
      }
    }

    // 3. Parallel Database context gathering
    const [evidenceDoc, caseDoc, atsDoc, dashboardMetrics, recentLogs] = await Promise.all([
      activeEvidenceId && mongoose.Types.ObjectId.isValid(activeEvidenceId) ? Content.findById(activeEvidenceId) : Promise.resolve(null),
      activeCaseId && mongoose.Types.ObjectId.isValid(activeCaseId) ? Case.findById(activeCaseId).populate('evidence') : Promise.resolve(null),
      ATSReport.findOne({ owner: req.user.userId })
        .populate('resumeId', 'fileName')
        .populate('jobDescriptionId', 'title')
        .sort({ createdAt: -1 }),
      Promise.all([
        Case.countDocuments(),
        Content.countDocuments(),
        Case.countDocuments({ status: { $in: ['open', 'in-progress'] } }),
        Content.countDocuments({ status: 'verified' }),
        Content.countDocuments({ status: 'flagged' })
      ]).then(([totalCases, totalEvidence, activeCases, verifiedCount, flaggedCount]) => ({
        totalCases, totalEvidence, activeCases, verifiedCount, flaggedCount
      })),
      AuditLog.find()
        .populate('performedBy', 'name role')
        .sort({ timestamp: -1 })
        .limit(10)
    ]);

    let userContextStr = `Name: ${req.user.name}\nRole: ${req.user.role}\nAccount Type: ${req.user.role === 'admin' ? 'Administrator' : 'Standard'}`;
    let evidenceContextStr = '';
    let caseContextStr = '';
    let routeContextStr = '';
    let dashboardContextStr = '';
    let auditContextStr = '';
    let atsContextStr = '';

    if (evidenceDoc) {
      const finding = await AIAnalysisResult.findOne({ contentId: evidenceDoc._id });
      evidenceContextStr = `Filename: ${evidenceDoc.title}
Mime Type: ${evidenceDoc.mimeType || 'unknown'}
Original Hash: ${evidenceDoc.originalHash}
Merkle Root: ${evidenceDoc.merkleRoot || 'Not generated'}
Integrity Status: ${evidenceDoc.status}
Verification Status: ${evidenceDoc.status}
Provenance Details:
- Derivation Type: ${evidenceDoc.derivationType || 'original'}
- Authenticity Score: ${evidenceDoc.authenticityScore}%
- Provenance Score: ${evidenceDoc.provenanceScore}%
- Metadata Risk Score: ${evidenceDoc.metadataRiskScore}%
- Integrity Score: ${evidenceDoc.integrityVerificationScore}%
- Confidence: ${evidenceDoc.verificationConfidence}%`;

      if (finding) {
        evidenceContextStr += `\nAI Diagnostic Findings:
- Verdict: ${finding.status === 'completed' ? 'Analysis Complete' : 'Pending'}
- Findings: ${finding.metadataFindings}
- Forensic Report: ${finding.forensicReport || 'None'}`;
      }
    }

    if (caseDoc) {
      caseContextStr = `Title: ${caseDoc.title}
Description: ${caseDoc.description || 'No description provided.'}
Status: ${caseDoc.status}
Severity: ${caseDoc.severity}
Evidence Count: ${caseDoc.evidence ? caseDoc.evidence.length : 0}
Evidence Details:\n`;

      if (caseDoc.evidence && caseDoc.evidence.length > 0) {
        caseDoc.evidence.forEach(ev => {
          caseContextStr += `- ${ev.title} (${ev.contentType}, Status: ${ev.status}, Integrity: ${ev.integrityVerificationScore}%)\n`;
        });
      } else {
        caseContextStr += `- No evidence linked.\n`;
      }

      if (caseDoc.notes && caseDoc.notes.length > 0) {
        caseContextStr += `Case Notes:\n`;
        caseDoc.notes.forEach(note => {
          caseContextStr += `- ${new Date(note.createdAt).toLocaleDateString()}: ${note.text}\n`;
        });
      }
    }

    if (atsDoc) {
      atsContextStr = `Latest ATS Report Details:
- Candidate Resume: ${atsDoc.resumeId?.fileName || 'unknown'}
- Applied Job: ${atsDoc.jobDescriptionId?.title || 'unknown'}
- Consensus Compatibility Score: ${atsDoc.scores.consensusScore}%
- Weighted Skill Score: ${atsDoc.scores.skillScore}%
- Experience Score: ${atsDoc.scores.experienceScore}%
- ATS Compatibility Score: ${atsDoc.scores.atsCompatibilityScore}%
- Responsibility Coverage: ${atsDoc.scores.responsibilityCoverage}%
- Role Detected: ${atsDoc.analysis.role || 'unknown'}
- Seniority Career Level: ${atsDoc.analysis.careerLevel || 'unknown'}
- Missing Skills: ${atsDoc.analysis.missingSkills.join(', ') || 'None'}
- ATS Formatting/Layout Issues: ${atsDoc.analysis.compatibilityIssues.join(', ') || 'None'}
- Structure Issues: ${atsDoc.analysis.structureIssues.join(', ') || 'None'}
- Recruiter Recommendations: ${atsDoc.analysis.recommendations.join(', ') || 'None'}`;
    }

    routeContextStr = `Current Path: ${currentRoute || 'unknown'}\nPlatform Map:\n`;
    for (const [route, desc] of Object.entries(SITE_MAP)) {
      routeContextStr += `- ${route}: ${desc}\n`;
    }

    if (dashboardMetrics) {
      dashboardContextStr = `Active Cases: ${dashboardMetrics.activeCases}
Total Cases: ${dashboardMetrics.totalCases}
Verified Files: ${dashboardMetrics.verifiedCount}
Flagged Files: ${dashboardMetrics.flaggedCount}`;
    }

    if (recentLogs && recentLogs.length > 0) {
      auditContextStr = 'Last 10 System Activity Events:\n';
      recentLogs.forEach(log => {
        auditContextStr += `- ${new Date(log.timestamp).toISOString()} - ${log.action} on ${log.entityType}: Performed by ${log.performedBy?.name || 'System'} (${log.performedBy?.role || 'Operator'})\n`;
      });
    }

    // 4. Context Ranking Engine
    const contextBlock = rankAndFilterContext(intent, {
      userContextStr,
      evidenceContextStr,
      caseContextStr,
      routeContextStr,
      dashboardContextStr,
      auditContextStr,
      atsContextStr
    });

    // 5. Persona-Based Prompt Selection
    let expertPrompt = '';
    if (intent === 'ATS_ANALYSIS') {
      expertPrompt = ATS_EXPERT_PROMPT;
    } else if (intent === 'CASE_ANALYSIS' || intent === 'EVIDENCE_ANALYSIS' || intent === 'REPORT_GENERATION') {
      expertPrompt = INVESTIGATION_EXPERT_PROMPT;
    }

    const systemPrompt = `${MASTER_SYSTEM_PROMPT}\n\n${expertPrompt}\n\n${contextBlock}\n\nPlease formulate your reply following the system instructions and quality rules.`;

    const structuredContext = {
      user: {
        name: req.user.name,
        role: req.user.role
      },
      currentRoute,
      evidence: evidenceDoc,
      case: caseDoc,
      ats: atsDoc,
      dashboard: dashboardMetrics,
      recentActivities: recentLogs
    };

    // Update global debug info state
    lastChatDebugInfo = {
      provider: isProviderConfigured() ? (process.env.AI_PROVIDER || 'GEMINI').toUpperCase() : 'Offline Engine',
      intent,
      route: currentRoute || '/dashboard',
      selectedCase: !!caseDoc,
      selectedEvidence: !!evidenceDoc,
      atsLoaded: !!atsDoc,
      historyMessages: history.length,
      responseSource: isProviderConfigured() ? 'online' : 'offline'
    };

    // 6. Generate Response
    let reply = await generateAIResponse(systemPrompt, history, message, structuredContext);

    // 7. Response Quality Guard & Self-Evaluation Layer
    if (!selfEvaluate(reply, intent, message) || !evaluateResponseQuality(reply, intent)) {
      console.log("Self-evaluation or quality guard failed. Regenerating once...");
      const correctivePrompt = `${systemPrompt}\n\n[SELF-EVALUATION WARNING] Ensure you explain what information is currently available in the context and provide a direct answer with explanation and next steps. Do not use generic template placeholders or state access failures.`;
      reply = await generateAIResponse(correctivePrompt, history, message, structuredContext);

      // Force conversational offline response if LLM continues to fail quality guard
      if (!selfEvaluate(reply, intent, message) || !evaluateResponseQuality(reply, intent)) {
        const { generateOfflineResponse } = require('../utils/aiProvider');
        reply = generateOfflineResponse(message, structuredContext, history, intent);
        lastChatDebugInfo.responseSource = 'offline';
      }
    }

    // 8. Stream output if client requested it
    const isStream = req.body.stream || req.headers.accept === 'text/event-stream';
    if (isStream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');

      const words = reply.split(/(\s+)/);
      for (const word of words) {
        res.write(`data: ${JSON.stringify({ chunk: word })}\n\n`);
        await new Promise(resolve => setTimeout(resolve, 15));
      }
      res.write('data: [DONE]\n\n');
      res.end();
      return;
    }

    return res.status(200).json({ response: reply });
  } catch (error) {
    console.error("AI PROVIDER ERROR:", error);
    try {
      const { generateOfflineResponse } = require('../utils/aiProvider');
      const intent = classifyIntent(req.body.message || "hi", req.body.history || []);
      const fallbackReply = generateOfflineResponse(
        req.body.message || "hi",
        {
          user: {
            name: req.user.name,
            role: req.user.role
          },
          currentRoute: req.body.currentRoute,
          evidence: null,
          case: null,
          ats: null,
          dashboard: null,
          recentActivities: null
        },
        req.body.history || [],
        intent
      );
      
      lastChatDebugInfo = {
        provider: isProviderConfigured() ? (process.env.AI_PROVIDER || 'GEMINI').toUpperCase() : 'Offline Engine',
        intent,
        route: req.body.currentRoute || '/dashboard',
        selectedCase: false,
        selectedEvidence: false,
        atsLoaded: false,
        historyMessages: (req.body.history || []).length,
        responseSource: 'offline'
      };

      const isStream = req.body.stream || req.headers.accept === 'text/event-stream';
      if (isStream) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        
        const words = fallbackReply.split(/(\s+)/);
        for (const word of words) {
          res.write(`data: ${JSON.stringify({ chunk: word })}\n\n`);
          await new Promise(resolve => setTimeout(resolve, 15));
        }
        res.write('data: [DONE]\n\n');
        res.end();
        return;
      }
      
      return res.status(200).json({ response: fallbackReply });
    } catch (innerError) {
      return res.status(200).json({
        response: "I am currently running in **Offline Intelligence Mode**. I can help you summarize cases, review ATS resume profiles, explain evidence files, or navigate to pages when you type requests like 'go to dashboard' or 'open cases'."
      });
    }
  }
}

module.exports = {
  handleChat,
  getLastChatDebugInfo
};
