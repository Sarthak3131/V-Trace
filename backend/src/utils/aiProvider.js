'use strict';

const { GoogleGenerativeAI } = require('@google/generative-ai');

/**
 * Checks if the configured AI provider has the required keys.
 * @returns {boolean}
 */
function isProviderConfigured() {
  const provider = (process.env.AI_PROVIDER || 'GEMINI').toUpperCase();
  const geminiKey = process.env.GEMINI_API_KEY;
  const openRouterKey = process.env.OPENROUTER_API_KEY;

  if (provider === 'GEMINI') {
    return !!geminiKey && geminiKey !== 'DUMMY_KEY';
  }
  if (provider === 'OPENROUTER') {
    return !!openRouterKey;
  }
  return false;
}

/**
 * Classifies user intent based on message content and history.
 * @param {string} message 
 * @param {Array} history 
 * @returns {string}
 */
function classifyIntent(message, history) {
  const msgLower = message.trim().toLowerCase();
  
  // 1. GREETING detection (Must NEVER trigger Case Analysis)
  const greetingWords = ['hi', 'hello', 'hey', 'yo', 'greetings', 'good morning', 'good afternoon', 'good evening', 'how are you', 'howdy'];
  const isGreeting = greetingWords.some(word => 
    msgLower === word || 
    msgLower.startsWith(word + ' ') || 
    msgLower.startsWith(word + ',') || 
    msgLower.startsWith(word + '!') ||
    msgLower === 'hey there' ||
    msgLower === 'hi there'
  );
  if (isGreeting) {
    return 'GREETING';
  }

  // 2. GENERAL_HELP detection
  if (
    msgLower.includes('help') || 
    msgLower.includes('what can you do') || 
    msgLower.includes('capabilities') || 
    msgLower.includes('commands') || 
    msgLower.includes('option') ||
    msgLower.includes('who are you') ||
    msgLower.includes('what can you help me with') ||
    msgLower.includes('what can you help')
  ) {
    return 'GENERAL_HELP';
  }

  // 3. NAVIGATION detection
  if (
    msgLower.includes('navigate') || 
    msgLower.includes('go to') || 
    msgLower.includes('open') || 
    msgLower.includes('show page') || 
    msgLower.includes('take me to') ||
    msgLower.includes('redirect') ||
    msgLower.includes('switch to')
  ) {
    return 'NAVIGATION';
  }

  // 4. REPORT_GENERATION detection
  if (
    (msgLower.includes('generate') || msgLower.includes('create') || msgLower.includes('make')) && 
    (msgLower.includes('report') || msgLower.includes('summary document') || msgLower.includes('timeline'))
  ) {
    return 'REPORT_GENERATION';
  }

  // 5. ATS_ANALYSIS detection
  if (
    msgLower.includes('ats') || 
    msgLower.includes('resume') || 
    msgLower.includes('score') || 
    msgLower.includes('skills') || 
    msgLower.includes('job description') || 
    msgLower.includes('jd') || 
    msgLower.includes('recruiter') || 
    msgLower.includes('benchmark') ||
    msgLower.includes('probability') ||
    msgLower.includes('career') ||
    msgLower.includes('seniority') ||
    msgLower.includes('roadmap') ||
    msgLower.includes('progression') ||
    msgLower.includes('learn') ||
    msgLower.includes('coverage') ||
    msgLower.includes('responsibility') ||
    msgLower.includes('improve') ||
    msgLower.includes('missing')
  ) {
    return 'ATS_ANALYSIS';
  }

  // 6. CASE_ANALYSIS detection
  if (
    msgLower.includes('case') || 
    msgLower.includes('investigation') || 
    msgLower.includes('severity') || 
    msgLower.includes('incident') ||
    msgLower.includes('notes')
  ) {
    return 'CASE_ANALYSIS';
  }

  // 7. EVIDENCE_ANALYSIS detection
  if (
    msgLower.includes('evidence') || 
    msgLower.includes('file') || 
    msgLower.includes('hash') || 
    msgLower.includes('integrity') || 
    msgLower.includes('provenance') || 
    msgLower.includes('metadata') ||
    msgLower.includes('forensic') ||
    msgLower.includes('suspicious') ||
    msgLower.includes('authenticity') ||
    msgLower.includes('flagged')
  ) {
    return 'EVIDENCE_ANALYSIS';
  }

  // 8. DASHBOARD_QUERY detection
  if (
    msgLower.includes('dashboard') || 
    msgLower.includes('metric') || 
    msgLower.includes('stat') || 
    msgLower.includes('summary') || 
    msgLower.includes('log') || 
    msgLower.includes('activity') ||
    msgLower.includes('history') ||
    msgLower.includes('audit')
  ) {
    return 'DASHBOARD_QUERY';
  }

  // 9. FOLLOW_UP detection
  const isFollowUp = history && history.length > 0 && (
    msgLower.includes('it') || 
    msgLower.includes('them') || 
    msgLower.includes('that') || 
    msgLower.includes('this') || 
    msgLower.includes('why') || 
    msgLower.includes('explain') || 
    msgLower.includes('how') ||
    msgLower.includes('risks') ||
    msgLower.includes('improve')
  );
  if (isFollowUp) {
    return 'FOLLOW_UP';
  }

  return 'GENERAL_HELP';
}

/**
 * Generates an offline intelligence response based on user query and platform context.
 * @param {string} userMessage
 * @param {Object} context
 * @param {Array} history
 * @param {string} [preClassifiedIntent]
 * @returns {string}
 */
function generateOfflineResponse(userMessage, context, history, preClassifiedIntent) {
  const msgLower = userMessage.toLowerCase();
  const chatHistory = history || [];

  // Centralized Route Mapping for Navigation Heuristics
  const routeMap = {
    dashboard: '/dashboard',
    ats: '/ats',
    cases: '/cases',
    evidence: '/content',
    reports: '/plagiarism',
    profile: '/profile',
    settings: '/settings'
  };

  // Classify Intent
  const intent = preClassifiedIntent || classifyIntent(userMessage, history);
  
  // Resolve Memory / Follow-up topics
  let resolvedIntent = intent;
  if (intent === 'FOLLOW_UP') {
    // Traverse history to check what was discussed previously to find a base intent
    for (let i = chatHistory.length - 1; i >= 0; i--) {
      const prevIntent = classifyIntent(chatHistory[i].content, []);
      if (prevIntent !== 'GENERAL_HELP' && prevIntent !== 'GREETING' && prevIntent !== 'NAVIGATION' && prevIntent !== 'FOLLOW_UP') {
        resolvedIntent = prevIntent;
        break;
      }
    }
    // Fallback based on currentRoute if no historical intent found
    if (resolvedIntent === 'FOLLOW_UP' && context?.currentRoute) {
      const routeLower = context.currentRoute.toLowerCase();
      if (routeLower.includes('ats')) resolvedIntent = 'ATS_ANALYSIS';
      else if (routeLower.includes('cases')) resolvedIntent = 'CASE_ANALYSIS';
      else if (routeLower.includes('content') || routeLower.includes('evidence')) resolvedIntent = 'EVIDENCE_ANALYSIS';
      else if (routeLower.includes('audit')) resolvedIntent = 'DASHBOARD_QUERY';
      else if (routeLower.includes('dashboard')) resolvedIntent = 'DASHBOARD_QUERY';
    }
  }

  // 1. Check for Navigation Intent
  let navTrigger = '';
  if (resolvedIntent === 'NAVIGATION' || msgLower.includes('go to') || msgLower.includes('open') || msgLower.includes('take me to') || msgLower.includes('show')) {
    if (msgLower.includes('dashboard')) {
      navTrigger = ` [NAVIGATE:${routeMap.dashboard}]`;
    } else if (msgLower.includes('ats') || msgLower.includes('resume')) {
      navTrigger = ` [NAVIGATE:${routeMap.ats}]`;
    } else if (msgLower.includes('case')) {
      navTrigger = ` [NAVIGATE:${routeMap.cases}]`;
    } else if (msgLower.includes('evidence') || msgLower.includes('library') || msgLower.includes('file')) {
      navTrigger = ` [NAVIGATE:${routeMap.evidence}]`;
    } else if (msgLower.includes('report') || msgLower.includes('plagiarism') || msgLower.includes('reports')) {
      navTrigger = ` [NAVIGATE:${routeMap.reports}]`;
    } else if (msgLower.includes('profile')) {
      navTrigger = ` [NAVIGATE:${routeMap.profile}]`;
    } else if (msgLower.includes('settings')) {
      navTrigger = ` [NAVIGATE:${routeMap.settings}]`;
    }
  }

  // If the query was purely a navigation command, respond directly
  if (navTrigger && msgLower.length < 35) {
    const routeName = Object.keys(routeMap).find(k => msgLower.includes(k)) || 'requested page';
    return `Sure! Navigating to the ${routeName} page.${navTrigger} [ACTIONS:Explain ATS Score|Review Latest Report|Go To Dashboard|Open Settings]`;
  }

  let reply = '';
  let actionsStr = '';

  // 2. Response Builder by Intent
  if (resolvedIntent === 'GREETING') {
    const userName = context?.user?.name ? context.user.name.split(' ')[0] : 'Sarthak';
    reply = `Hello ${userName}. I'm V-Trace AI Copilot. I can help analyze ATS reports, investigate evidence, summarize cases, explain dashboard metrics, and navigate the platform.`;
    actionsStr = ' [ACTIONS:Explain ATS Score|Review Latest Report|Go To Dashboard|Open Settings]';
  } 
  
  else if (resolvedIntent === 'GENERAL_HELP') {
    reply = `I can assist with:\n• ATS optimization\n• Resume analysis\n• Investigation workflows\n• Evidence review\n• Dashboard insights\n• Site navigation`;
    actionsStr = ' [ACTIONS:Explain ATS Score|Review Latest Report|Go To Dashboard|Open Settings]';
  }

  else if (resolvedIntent === 'NAVIGATION') {
    const routeName = Object.keys(routeMap).find(k => msgLower.includes(k)) || 'requested page';
    reply = `Certainly. I am taking you to the ${routeName} page right away. Let me know if you need help analyzing anything there!`;
    actionsStr = ' [ACTIONS:Explain ATS Score|Review Latest Report|Go To Dashboard|Open Settings]';
  }
  
  else if (resolvedIntent === 'ATS_ANALYSIS') {
    const ats = context?.ats;
    
    // Check if general query first
    if (msgLower.includes('tell me about') || msgLower.includes('what are') || msgLower.includes('what is')) {
      reply = `ATS scores estimate how well a resume aligns with a job description. They are usually influenced by skills, responsibilities, experience alignment, formatting, and recruiter relevance.`;
    } else if (ats) {
      const jobTitle = ats.jobDescriptionId?.title || 'the target position';
      const consensus = ats.scores?.consensusScore ?? 0;
      const skills = ats.scores?.skillScore ?? 0;
      const exp = ats.scores?.experienceScore ?? 0;
      const rec = ats.scores?.recruiterScore ?? 0;
      const jdCoverage = ats.scores?.jdCoverageScore ?? 0;
      const responsibility = ats.scores?.responsibilityCoverage ?? 0;
      const missingSkillsList = ats.analysis?.missingSkills || [];
      const issuesList = ats.analysis?.compatibilityIssues || [];
      const recList = ats.analysis?.recommendations || [];
      const benchmarkReliability = ats.analysis?.benchmarkReliability || 'Low';
      const benchmarkRank = ats.analysis?.benchmarkRank || 'Average';
      const careerLevel = ats.analysis?.careerLevel || 'Junior';
      const yearsOfExperience = ats.analysis?.yearsOfExperience || 0;
      const recruiterConfidence = ats.analysis?.recruiterConfidence ?? rec;

      if (msgLower.includes('why') && (msgLower.includes('low') || msgLower.includes('fail') || msgLower.includes('reject'))) {
        let reasons = [];
        if (skills < 70) reasons.push(`Your skill alignment score is relatively low (${skills}%).`);
        if (exp < 70) reasons.push(`There is an experience year gap parsed from your resume (${yearsOfExperience} years detected).`);
        if (issuesList.length > 0) reasons.push(`We identified layout formatting issues: ${issuesList.join(', ')}.`);
        if (missingSkillsList.length > 0) reasons.push(`Core skills required for ${jobTitle} are missing.`);
        
        reply = `### ATS Evaluation Breakdown\n\nYour consensus score is **${consensus}%** for the **${jobTitle}** role. Here are the primary factors affecting your score:\n\n- ${reasons.length > 0 ? reasons.join('\n- ') : 'No critical formatting or skill gaps identified.'}\n\nTo improve, focus on aligning missing keywords and adjusting your resume layout.`;
      } else if (msgLower.includes('missing') || msgLower.includes('what should i learn') || msgLower.includes('learn next') || msgLower.includes('skills')) {
        const skillsText = missingSkillsList.length > 0
          ? `The following skills are missing from your resume compared to the job description:\n\n${missingSkillsList.map(s => `- **${s}**`).join('\n')}\n\n**Recommendation**: Incorporate these skills in your experience bullet points with quantitative results.`
          : `Congratulations! Your resume lists all critical skills identified in the job description.`;
        reply = `### Missing Skills Audit\n\n${skillsText}`;
      } else if (msgLower.includes('improve') || msgLower.includes('how can i') || msgLower.includes('how do i')) {
        const suggestions = recList.length > 0
          ? recList.map(r => `- ${r}`).join('\n')
          : '- Ensure bullet points contain strong action verbs.\n- Structure dates in standard MM/YYYY formats.\n- Avoid double-column layouts or nested tables.';
        reply = `### ATS Score Improvement Suggestions\n\nBased on your report for **${jobTitle}**:\n\n${suggestions}`;
      } else if (msgLower.includes('recruiter') || msgLower.includes('confidence')) {
        reply = `### Recruiter Confidence Evaluation\n\n- **Recruiter Score**: **${rec}%**\n- **Confidence**: **${recruiterConfidence}%**\n- **Standing**: Classified as career level **${careerLevel}**.\n\nRecruiter Confidence measures the readability, experience duration, and structural alignment of your resume relative to actual recruiter screening preferences.`;
      } else if (msgLower.includes('reliability') || msgLower.includes('benchmark')) {
        reply = `### Database Benchmarking Standing\n\nYour profile ranks with a compatibility of **${consensus}%** against the job profile.\n\n- **Benchmark Standing**: ${benchmarkRank}\n- **Benchmark Reliability**: ${benchmarkReliability}\n\nThe benchmark standing compares your compatibility against all other scanned applicants in the database for the **${jobTitle}** role.`;
      } else if (msgLower.includes('responsibility') && msgLower.includes('coverage')) {
        reply = `### Responsibility Coverage Analysis\n\n- **Responsibility Coverage**: **${responsibility}%**\n\nThis score represents the semantic alignment between your candidate experience bullet points and the specific duties, tasks, and responsibilities detailed in the job description.`;
      } else if (msgLower.includes('coverage')) {
        reply = `### Job Description Coverage Analysis\n\n- **JD Coverage Score**: **${jdCoverage}%**\n- **Responsibility Coverage**: **${responsibility}%**\n- **Skill Match**: **${skills}%**\n- **Experience Match**: **${exp}%**\n\nThis metrics weighs matching technical skills (50%), responsibility mapping (30%), and chronological experience duration (20%).`;
      } else {
        reply = `### ATS Compatibility Insights\n\n- **Job Position**: ${jobTitle}\n- **Consensus Compatibility**: **${consensus}%**\n- **JD Coverage**: **${jdCoverage}%**\n- **Responsibility Match**: ${responsibility}%\n- **Recruiter Confidence**: ${recruiterConfidence}%\n\nYou can ask: "Why is my score low?", "How can I improve it?", or "What skills are missing?".`;
      }
    } else {
      reply = `I don't currently see any scanned resume or ATS report for your profile.\n\nYou can:\n• Go to the ATS Page and upload your resume for analysis.\n• Review active cases or investigate evidence.\n\nWould you like me to take you to the ATS scan page? [NAVIGATE:${routeMap.ats}]`;
    }
    actionsStr = ' [ACTIONS:Show Missing Skills|Explain Recruiter Confidence|Improve ATS Score|Open ATS Dashboard]';
  } 
  
  else if (resolvedIntent === 'CASE_ANALYSIS') {
    const kase = context?.case;
    if (kase) {
      const evidenceList = kase.evidence && kase.evidence.length > 0
        ? kase.evidence.map(e => `- **${e.title}** (${e.contentType}, Status: ${e.status}, Integrity: ${e.integrityVerificationScore}%)`).join('\n')
        : '- No evidence items currently linked.';
      const notesList = kase.notes && kase.notes.length > 0
        ? kase.notes.map(n => `- *${new Date(n.createdAt).toLocaleDateString()}*: ${n.text}`).join('\n')
        : '- No notes recorded.';

      if (msgLower.includes('summarize')) {
        reply = `### Case Summary: ${kase.title}\n\n- **Status**: **${kase.status.toUpperCase()}**\n- **Severity**: **${kase.severity.toUpperCase()}**\n- **Description**: ${kase.description || 'No description provided.'}\n\n**Evidence Overview**:\n${evidenceList}`;
      } else if (msgLower.includes('evidence') || msgLower.includes('file')) {
        reply = `### Case Evidence Ledger: ${kase.title}\n\nThe following evidence files are associated with this investigation:\n\n${evidenceList}`;
      } else if (msgLower.includes('risk') || msgLower.includes('flag')) {
        const flaggedCount = kase.evidence ? kase.evidence.filter(e => e.status === 'flagged').length : 0;
        reply = `### Case Risk Assessment\n\n- **Overall Severity**: ${kase.severity.toUpperCase()}\n- **Flagged Files**: ${flaggedCount}\n\nWarning: Flagged evidence files indicate integrity mismatches or metadata anomalies that require immediate review.`;
      } else if (msgLower.includes('status') || msgLower.includes('investigation status')) {
        reply = `### Case Investigation Status: ${kase.title}\n\n- **Current Status**: **${kase.status.toUpperCase()}**\n- **Investigation Severity**: **${kase.severity.toUpperCase()}**\n\nThe case is currently marked as **${kase.status}** with severity set to **${kase.severity}**.`;
      } else if (msgLower.includes('timeline') || msgLower.includes('activity')) {
        reply = `### Case Timeline & Notes\n\nRecent activity and notes logged for **${kase.title}**:\n\n${notesList}`;
      } else {
        reply = `### Case Overview: ${kase.title}\n\n- **Status**: ${kase.status.toUpperCase()}\n- **Severity**: ${kase.severity.toUpperCase()}\n- **Description**: ${kase.description || 'No description provided.'}\n\n**Evidence Overview**:\n${evidenceList}`;
      }
    } else {
      reply = `I don't currently see an active case selected.\n\nYou can:\n• Open a case for investigation\n• Review ATS reports\n• Analyze evidence files\n• Navigate the platform\n\nWhat would you like to do?`;
    }
    actionsStr = ' [ACTIONS:Summarize Case|Show Evidence|Highlight Risks|Generate Timeline]';
  } 
  
  else if (resolvedIntent === 'EVIDENCE_ANALYSIS') {
    const ev = context?.evidence;
    if (ev) {
      if (msgLower.includes('metadata')) {
        reply = `### Evidence Metadata Audit: ${ev.title}\n\n- **File Name**: ${ev.title}\n- **Mime Type**: ${ev.mimeType || 'unknown'}\n- **File Size**: ${(ev.fileSize / 1024).toFixed(2)} KB\n- **Storage Key**: ${ev.metadata?.storageKey || 'Local'}\n\n**Status**: Metadata check returns **${ev.status.toUpperCase()}**.`;
      } else if (msgLower.includes('provenance')) {
        reply = `### Evidence Provenance & Lineage\n\n- **Derivation Type**: ${ev.derivationType || 'original'}\n- **Provenance Score**: **${ev.provenanceScore}%**\n\nThis indicates the authenticity level of origin signatures and ownership record tracing.`;
      } else if (msgLower.includes('verification status') || msgLower.includes('verify')) {
        reply = `### Evidence Verification Status: ${ev.title}\n\n- **Status**: **${ev.status.toUpperCase()}**\n- **Integrity Score**: **${ev.integrityVerificationScore}%**\n- **Verification Confidence**: **${ev.verificationConfidence}%**\n\nThe verification status for this file is currently **${ev.status}** with a confidence score of **${ev.verificationConfidence}%**.`;
      } else if (msgLower.includes('risk') || msgLower.includes('flag')) {
        reply = `### Evidence Forensic Risks: ${ev.title}\n\n- **Metadata Risk**: **${ev.metadataRiskScore}%**\n- **Integrity Score**: **${ev.integrityVerificationScore}%**\n- **Confidence**: **${ev.verificationConfidence}%**\n\nVerdict: ${ev.status === 'flagged' ? 'High risk detected. Inconsistent headers or modified tags found.' : 'Low risk. Hashes are consistent.'}`;
      } else {
        reply = `### Evidence Analysis: ${ev.title}\n\n- **Type**: ${ev.contentType}\n- **Status**: ${ev.status.toUpperCase()}\n- **Hash**: \`${ev.originalHash}\`\n- **Integrity Score**: **${ev.integrityVerificationScore}%**`;
      }
    } else {
      reply = `I don't currently see a specific evidence file selected.\n\nYou can:\n• Open the Evidence Library to choose a file.\n• Upload a new file in the authenticity scanner.\n\nWhat would you like me to take you to?`;
    }
    actionsStr = ' [ACTIONS:Analyze Evidence|Check Metadata Risks|View Provenance Details]';
  } 
  
  else if (resolvedIntent === 'DASHBOARD_QUERY') {
    const db = context?.dashboard;
    const logs = context?.recentActivities;
    const logsStr = logs && logs.length > 0 
      ? logs.slice(0, 5).map(l => `- **${new Date(l.timestamp).toLocaleTimeString()}**: ${l.action} on ${l.entityType} by ${l.performedBy?.name || 'System'}`).join('\n')
      : '- No recent activity logs.';

    if (msgLower.includes('how many active') || msgLower.includes('active cases')) {
      reply = `### Active Cases Count\n\nThere are currently **${db?.activeCases || 0}** active investigations/cases on the dashboard.`;
    } else if (msgLower.includes('attention') || msgLower.includes('action') || msgLower.includes('flag')) {
      reply = `### Dashboard Action Items\n\n- Flagged Files: **${db?.flaggedCount || 0}**\n- Active Investigations: **${db?.activeCases || 0}**\n\nPlease review flagged evidence and in-progress cases requiring attention.`;
    } else if (msgLower.includes('summary') || msgLower.includes('system summary') || msgLower.includes('dashboard')) {
      reply = `### System Summary Report\n\n- **Active investigations**: ${db?.activeCases || 0}\n- **Total Scanned Evidence**: ${db?.totalEvidence || 0}\n- **Security Mismatches (Flagged)**: ${db?.flaggedCount || 0}\n- **Clean Signatures (Verified)**: ${db?.verifiedCount || 0}`;
    } else if (msgLower.includes('activity') || msgLower.includes('recent activity')) {
      reply = `### Recent Activity Log Events\n\n${logsStr}`;
    } else {
      reply = `### Dashboard Status Summary\n\n- **Active Cases**: ${db?.activeCases || 0} (of ${db?.totalCases || 0} total cases)\n- **Verified Files**: ${db?.verifiedCount || 0}\n- **Flagged Files**: ${db?.flaggedCount || 0}`;
    }
    actionsStr = ' [ACTIONS:Show Dashboard Summary|View Flagged Files|View Activity Logs|Open Settings]';
  } 
  
  else if (resolvedIntent === 'REPORT_GENERATION') {
    const kase = context?.case;
    if (kase) {
      reply = `### Investigation Report: ${kase.title}\n\n**1. Executive Summary**\nStatus: ${kase.status.toUpperCase()} | Severity: ${kase.severity.toUpperCase()}\nDescription: ${kase.description || 'No description provided.'}\n\n**2. Evidence Details**\n${kase.evidence && kase.evidence.length > 0 ? kase.evidence.map(e => `- ${e.title} (${e.contentType}, Status: ${e.status})`).join('\n') : '- No evidence linked.'}`;
    } else {
      reply = `I don't currently see an active case selected.\n\nYou can:\n• Open a case for investigation\n• Review ATS reports\n• Analyze evidence files\n• Navigate the platform\n\nWhat would you like to do?`;
    }
    actionsStr = ' [ACTIONS:Summarize Case|Show Evidence|Highlight Risks|Generate Timeline]';
  } 
  
  else {
    reply = `I can help you analyze resume scores, summarize active security cases, review forensic evidence files, check system audit logs, and navigate V-Trace.\n\nYou can ask me:\n• "Explain my ATS score"\n• "Summarize this case"\n• "Analyze this evidence"\n• "Explain recent activity"`;
    actionsStr = ' [ACTIONS:Explain ATS Score|Summarize Case|Show Dashboard Summary]';
  }

  return reply + navTrigger + actionsStr;
}

/**
 * Simulates streaming for offline content by delivering words with a slight delay.
 * @param {string} text
 * @param {function} onToken
 * @returns {Promise<void>}
 */
async function simulateOfflineStream(text, onToken) {
  const words = text.split(/(\s+)/);
  for (const word of words) {
    onToken(word);
    await new Promise(resolve => setTimeout(resolve, 15));
  }
}

/**
 * Generates chat response using the active AI provider, with optional token streaming.
 * @param {string} systemPrompt
 * @param {Array<{role: string, content: string}>} history
 * @param {string} userMessage
 * @param {Object} structuredContext
 * @param {function} [onToken]
 * @returns {Promise<string>}
 */
async function generateAIResponse(systemPrompt, history, userMessage, structuredContext, onToken) {
  const provider = (process.env.AI_PROVIDER || 'GEMINI').toUpperCase();
  const isConfigured = isProviderConfigured();

  if (!isConfigured) {
    console.log("LLM provider not configured. Falling back to Offline AI Engine.");
    const offlineReply = generateOfflineResponse(userMessage, structuredContext, history);
    if (onToken) {
      await simulateOfflineStream(offlineReply, onToken);
    }
    return offlineReply;
  }

  try {
    if (provider === 'GEMINI') {
      const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
      const model = genAI.getGenerativeModel({
        model: 'gemini-2.5-flash',
        systemInstruction: systemPrompt
      });

      const contents = history.map(h => ({
        role: h.role === 'user' ? 'user' : 'model',
        parts: [{ text: h.content }]
      }));

      contents.push({
        role: 'user',
        parts: [{ text: userMessage }]
      });

      if (onToken) {
        const result = await model.generateContentStream({ contents });
        let fullText = '';
        for await (const chunk of result.stream) {
          const text = chunk.text();
          fullText += text;
          onToken(text);
        }
        return fullText;
      } else {
        const response = await model.generateContent({ contents });
        return response.response.text();
      }
    }

    if (provider === 'OPENROUTER') {
      const openRouterKey = process.env.OPENROUTER_API_KEY;

      const messages = [
        { role: 'system', content: systemPrompt },
        ...history.map(h => ({
          role: h.role === 'user' ? 'user' : 'assistant',
          content: h.content
        })),
        { role: 'user', content: userMessage }
      ];

      const body = {
        model: 'google/gemini-2.5-flash',
        messages
      };

      if (onToken) {
        body.stream = true;
      }

      const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openRouterKey}`,
          'HTTP-Referer': 'https://v-trace.security',
          'X-Title': 'V-Trace AI Copilot'
        },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenRouter API error: ${response.status} - ${errorText}`);
      }

      if (onToken) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let fullText = '';
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunkStr = decoder.decode(value);
          const lines = chunkStr.split('\n');
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const dataStr = line.slice(6).trim();
              if (dataStr === '[DONE]') break;
              try {
                const dataObj = JSON.parse(dataStr);
                const text = dataObj.choices[0].delta.content || '';
                if (text) {
                  fullText += text;
                  onToken(text);
                }
              } catch (e) {
                // Ignore partial JSON parsing errors
              }
            }
          }
        }
        return fullText;
      } else {
        const data = await response.json();
        if (!data.choices || !data.choices[0] || !data.choices[0].message) {
          throw new Error('Unexpected OpenRouter API response structure.');
        }
        return data.choices[0].message.content;
      }
    }

    throw new Error(`Unsupported AI Provider: ${provider}`);
  } catch (error) {
    console.error("LLM Provider call failed. Falling back to Offline AI Engine. Error:", error);
    const offlineReply = generateOfflineResponse(userMessage, structuredContext, history);
    if (onToken) {
      await simulateOfflineStream(offlineReply, onToken);
    }
    return offlineReply;
  }
}

module.exports = {
  isProviderConfigured,
  generateOfflineResponse,
  generateAIResponse,
  classifyIntent
};
