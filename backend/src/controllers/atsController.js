'use strict';

const fs = require('fs');
const pdfParseModule = require('pdf-parse');
const mammoth = require('mammoth');
const mongoose = require('mongoose');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const ATSResume = require('../models/ATSResume');
const ATSJobDescription = require('../models/ATSJobDescription');
const ATSReport = require('../models/ATSReport');
const SkillKnowledgeBase = require('../models/SkillKnowledgeBase');
const { logEvent } = require('../utils/auditLogger');
const { computeSemanticSimilarity } = require('../utils/semanticHelper');

// ─── Document Parsing Helpers ──────────────────────────────────────────────────

async function extractTextFromBuffer(buffer, mimeType, filename) {
  const cleanMime = String(mimeType).trim().toLowerCase();
  const cleanName = String(filename).trim().toLowerCase();

  try {
    if (cleanMime === 'application/pdf' || cleanName.endsWith('.pdf')) {
      let parsedText = '';
      if (typeof pdfParseModule === 'function') {
        const data = await pdfParseModule(buffer);
        parsedText = data.text || '';
      } else if (pdfParseModule && pdfParseModule.PDFParse) {
        const instance = new pdfParseModule.PDFParse({ data: buffer });
        const result = await instance.getText();
        parsedText = result.text || '';
      } else {
        throw new Error('Unsupported pdf-parse module exports structure');
      }
      return parsedText;
    } else if (
      cleanMime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      cleanMime === 'application/msword' ||
      cleanName.endsWith('.docx')
    ) {
      const result = await mammoth.extractRawText({ buffer });
      return result.value || '';
    } else {
      // Fallback: treat as plain text UTF-8
      return buffer.toString('utf8');
    }
  } catch (err) {
    throw new Error(`Failed to parse file structure: ${err.message}`);
  }
}

// ─── Linguistic NLP & Keyword Helpers ──────────────────────────────────────────

const STOP_WORDS = new Set([
  'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'arent', 'as', 'at',
  'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by', 'cant', 'cannot', 'could',
  'did', 'didnt', 'do', 'does', 'doesnt', 'doing', 'dont', 'down', 'during', 'each', 'few', 'for', 'from', 'further',
  'had', 'hadnt', 'has', 'hasnt', 'have', 'havent', 'having', 'he', 'hed', 'hell', 'hes', 'her', 'here', 'heres',
  'hers', 'herself', 'him', 'himself', 'his', 'how', 'hows', 'i', 'id', 'ill', 'im', 'ive', 'if', 'in', 'into', 'is',
  'isnt', 'it', 'its', 'itself', 'lets', 'me', 'more', 'most', 'mustnt', 'my', 'myself', 'no', 'nor', 'not', 'of',
  'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same',
  'shant', 'she', 'shed', 'shell', 'shes', 'should', 'shouldnt', 'so', 'some', 'such', 'than', 'that', 'thats',
  'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', 'theres', 'these', 'they', 'theyd', 'theyll',
  'theyre', 'theyve', 'this', 'those', 'through', 'to', 'too', 'under', 'until', 'up', 'very', 'was', 'wasnt',
  'we', 'wed', 'well', 'were', 'weve', 'werent', 'what', 'whats', 'when', 'whens', 'where', 'wheres', 'which',
  'while', 'who', 'whos', 'whom', 'why', 'whys', 'with', 'wont', 'would', 'wouldnt', 'you', 'youd', 'youll',
  'youre', 'youve', 'your', 'yours', 'yourself', 'yourselves', 'can', 'will', 'use', 'using', 'experience', 'work',
  'team', 'project', 'projects', 'system', 'systems', 'development', 'management', 'responsibilities', 'key',
  // Generic words to completely ignore
  'application', 'applications', 'technology', 'technologies', 'modern', 'user', 'users', 'engineering',
  'interface', 'interfaces', 'operation', 'operations', 'participated', 'worked', 'used', 'solution', 'solutions'
]);

const MULTI_WORD_PHRASES = [
  'rest api', 'rest apis', 'data structures', 'algorithms', 'code review', 'code reviews',
  'responsive design', 'performance optimization', 'database operations', 'cloud deployment',
  'full stack development', 'software development lifecycle', 'unit testing', 'integration testing',
  'version control', 'object oriented programming'
];

function getKeywordWeight(keyword) {
  const kw = keyword.toLowerCase().trim();
  const tier1 = [
    'react', 'node', 'express', 'mongodb', 'mysql', 'postgresql', 'javascript', 'typescript', 'php', 'java', 'python', 'aws', 'docker', 'kubernetes', 'graphql', 'redis', 'git', 'github',
    'rest api', 'rest apis', 'data structures', 'algorithms', 'full stack development', 'software development lifecycle', 'unit testing', 'integration testing', 'version control', 'object oriented programming'
  ];
  const tier2 = [
    'debugging', 'testing', 'agile', 'deployment', 'responsive design', 'database operations', 'code review', 'code reviews', 'performance optimization', 'architecture', 'scalability', 'cloud deployment'
  ];
  const tier3 = [
    'developed', 'implemented', 'created', 'engineered', 'maintained', 'optimized', 'automated', 'collaborated', 'designed', 'built'
  ];
  
  if (tier1.includes(kw)) return 3;
  if (tier2.includes(kw)) return 2;
  if (tier3.includes(kw)) return 1;
  return 1; // Default weight
}

function extractKeywords(text, limit = 30) {
  let cleanedText = text.toLowerCase();
  const foundPhrases = [];
  
  // 1. Extract multi-word phrases
  for (const phrase of MULTI_WORD_PHRASES) {
    const escaped = phrase.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
    const regex = new RegExp(`\\b${escaped}\\b`, 'g');
    if (regex.test(cleanedText)) {
      foundPhrases.push(phrase);
      cleanedText = cleanedText.replace(regex, ' ');
    }
  }
  
  // 2. Tokenize remaining text
  const words = cleanedText
    .replace(/[^\w\s-]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 3 && !STOP_WORDS.has(w) && !/^\d+$/.test(w));

  const freqs = {};
  for (const w of words) {
    freqs[w] = (freqs[w] || 0) + 1;
  }

  const sortedWords = Object.entries(freqs)
    .sort((a, b) => b[1] - a[1])
    .map(entry => entry[0]);

  const combined = [...new Set([...foundPhrases, ...sortedWords])];
  return combined.slice(0, limit);
}

const ACTION_VERBS = [
  'built', 'developed', 'implemented', 'created', 'optimized',
  'improved', 'led', 'managed', 'automated', 'reduced', 'increased'
];

function extractActionVerbs(text) {
  const lowerText = text.toLowerCase();
  return ACTION_VERBS.filter(verb => {
    const regex = new RegExp(`\\b${verb}\\b`, 'i');
    return regex.test(lowerText);
  });
}

function parseContactInfo(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
  const phoneRegex = /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/;
  const linkedinRegex = /linkedin\.com\/in\/[a-zA-Z0-9_-]+/i;
  const githubRegex = /github\.com\/[a-zA-Z0-9_-]+/i;

  const emailMatch = text.match(emailRegex);
  const phoneMatch = text.match(phoneRegex);
  const linkedinMatch = text.match(linkedinRegex);
  const githubMatch = text.match(githubRegex);

  return {
    email: emailMatch ? emailMatch[0] : '',
    phone: phoneMatch ? phoneMatch[0] : '',
    linkedin: linkedinMatch ? linkedinMatch[0] : '',
    github: githubMatch ? githubMatch[0] : ''
  };
}

// ─── Synonym Groups For Action Matching ────────────────────────────────────────

const SYNONYM_GROUPS = [
  ['developed', 'created', 'built', 'implemented', 'engineered', 'designed'],
  ['optimized', 'improved', 'enhanced', 'accelerated'],
  ['collaborated', 'worked with', 'partnered', 'coordinated'],
  ['maintained', 'supported', 'managed', 'updated']
];

const SYNONYM_GROUPS_RESP = {
  'implemented': ["built", "created", "developed", "engineered", "designed", "implement", "build", "create", "develop", "engineer", "design"],
  'optimized': ["improved", "enhanced", "accelerated", "tuned", "optimize", "improve", "enhance", "accelerate", "tune"],
  'collaborated': ["worked with", "partnered", "coordinated", "participated", "collaborate", "partner", "coordinate", "participate", "work with"],
  'maintained': ["supported", "managed", "updated", "maintain", "support", "manage", "update"],
  'debugged': ["fixed", "troubleshooted", "resolved", "resolved issues", "debug", "fix", "troubleshoot", "resolve", "resolved issue"]
};

function evaluateKeywordMatch(resumeText, jdKeywords) {
  if (jdKeywords.length === 0) return 100;
  const lowerResume = resumeText.toLowerCase();
  let matchedWeight = 0;
  let totalWeight = 0;

  for (const kw of jdKeywords) {
    const lowerKw = kw.toLowerCase().trim();
    if (STOP_WORDS.has(lowerKw)) continue;

    const weight = getKeywordWeight(lowerKw);
    totalWeight += weight;

    let isMatch = lowerResume.includes(lowerKw);
    if (!isMatch) {
      const synGroup = SYNONYM_GROUPS.find(group => group.includes(lowerKw));
      if (synGroup) {
        isMatch = synGroup.some(syn => lowerResume.includes(syn));
      }
    }

    if (isMatch) {
      matchedWeight += weight;
    }
  }

  return totalWeight > 0 ? Math.round((matchedWeight / totalWeight) * 100) : 100;
}

function extractJdResponsibilitiesHeuristic(jdText) {
  const sentences = jdText.split(/[.\n]+/).map(s => s.trim()).filter(s => s.length > 15);
  const responsibilityVerbs = [
    'develop', 'build', 'create', 'design', 'implement', 'engineer', 'optimize', 'improve', 'enhance', 'accelerate',
    'collaborate', 'partner', 'coordinate', 'maintain', 'support', 'manage', 'update', 'debug', 'fix', 'troubleshoot',
    'resolve', 'test', 'write', 'lead', 'architect', 'deploy', 'configure', 'automate'
  ];
  
  const responsibilities = [];
  for (const sentence of sentences) {
    const words = sentence.toLowerCase().split(/\s+/);
    const hasVerb = words.slice(0, 4).some(word => responsibilityVerbs.includes(word));
    if (hasVerb && !sentence.toLowerCase().includes('requirements') && !sentence.toLowerCase().includes('qualifications')) {
      responsibilities.push(sentence);
    }
  }
  return responsibilities.slice(0, 8);
}

function matchResponsibility(resumeText, jdResp) {
  const lowerResume = resumeText.toLowerCase();
  const lowerResp = jdResp.toLowerCase();
  
  let matchedGroups = [];
  for (const [groupKey, groupVerbs] of Object.entries(SYNONYM_GROUPS_RESP)) {
    if (groupVerbs.some(verb => lowerResp.includes(verb))) {
      matchedGroups.push(groupKey);
    }
  }
  
  const words = lowerResp
    .replace(/[^\w\s-]/g, ' ')
    .split(/\s+/)
    .filter(w => {
      if (w.length <= 2) return false;
      if (STOP_WORDS.has(w)) return false;
      for (const verbs of Object.values(SYNONYM_GROUPS_RESP)) {
        if (verbs.includes(w)) return false;
      }
      return true;
    });
    
  if (words.length === 0) return false;
  
  let verbMatch = true;
  if (matchedGroups.length > 0) {
    verbMatch = matchedGroups.some(groupKey => {
      const resumeVerbs = SYNONYM_GROUPS_RESP[groupKey];
      return resumeVerbs.some(verb => lowerResume.includes(verb));
    });
  }
  
  const matchThreshold = Math.max(1, Math.ceil(words.length * 0.5));
  let matchedCount = 0;
  for (const word of words) {
    if (lowerResume.includes(word)) {
      matchedCount++;
    }
  }
  const subjectMatch = matchedCount >= matchThreshold;
  
  return verbMatch && subjectMatch;
}

// ─── Section-Aware Experience & Date Parser ───────────────────────────────────

function extractSections(text) {
  const sectionRegex = /(?:^|\n)([ \t]*(?:EXPERIENCE|WORK EXPERIENCE|PROFESSIONAL EXPERIENCE|EMPLOYMENT|PROJECTS|PERSONAL PROJECTS|KEY PROJECTS|ACADEMIC PROJECTS|EDUCATION|ACADEMIC BACKGROUND|CERTIFICATIONS|TRAINING|SKILLS|SUMMARY|OBJECTIVE)[ \t]*)(?:\n|\r|$)/gi;
  const headings = [];
  let match;

  while ((match = sectionRegex.exec(text)) !== null) {
    headings.push({
      name: match[1].trim().toUpperCase(),
      index: match.index,
      length: match[0].length
    });
  }

  if (headings.length === 0) {
    return { 'DEFAULT': text };
  }

  const result = {};
  const firstHeading = headings[0];
  if (firstHeading.index > 0) {
    result['DEFAULT'] = text.slice(0, firstHeading.index);
  }

  for (let i = 0; i < headings.length; i++) {
    const start = headings[i].index + headings[i].length;
    const end = (i + 1 < headings.length) ? headings[i + 1].index : text.length;
    const headingName = headings[i].name;
    result[headingName] = (result[headingName] || '') + '\n' + text.slice(start, end);
  }

  return result;
}

function parseExperienceYears(sections) {
  // Sum years only under experience headings
  const experienceKeys = ['EXPERIENCE', 'WORK EXPERIENCE', 'PROFESSIONAL EXPERIENCE', 'EMPLOYMENT'];
  let combinedText = '';
  
  for (const key of experienceKeys) {
    if (sections[key]) {
      combinedText += '\n' + sections[key];
    }
  }

  if (!combinedText.trim()) return 0;

  const yearRangeRegex = /\b(19|20\d{2})\s*[-–—]\s*(Present|(?:19|20)\d{2})\b/gi;
  const ranges = [];
  const currentYear = new Date().getFullYear();
  let match;

  while ((match = yearRangeRegex.exec(combinedText)) !== null) {
    const start = parseInt(match[1], 10);
    const endStr = match[2];
    const end = (endStr.toLowerCase() === 'present') ? currentYear : parseInt(endStr, 10);
    if (end >= start) {
      ranges.push({ start, end });
    }
  }

  if (ranges.length === 0) return 0;

  // Resolve overlapping ranges to prevent double-counting
  ranges.sort((a, b) => a.start - b.start);
  
  let mergedYears = 0;
  let currentRange = ranges[0];

  for (let i = 1; i < ranges.length; i++) {
    const nextRange = ranges[i];
    if (nextRange.start <= currentRange.end) {
      currentRange.end = Math.max(currentRange.end, nextRange.end);
    } else {
      mergedYears += (currentRange.end - currentRange.start);
      currentRange = nextRange;
    }
  }
  mergedYears += (currentRange.end - currentRange.start);

  if (mergedYears === 0 && ranges.length > 0) {
    mergedYears = 1;
  }

  return mergedYears;
}

// ─── Local Entity Extraction Helper ───────────────────────────────────────────

function extractLocalEntities(text, skillLookup) {
  const normalizedText = text.toLowerCase();
  const extracted = new Set();

  for (const [key, canonical] of skillLookup.entries()) {
    const escapedKey = key.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
    const regex = new RegExp(`(?:^|[^a-zA-Z0-9_#+.\\-])(${escapedKey})(?:$|[^a-zA-Z0-9_#+.\\-]|\\.(?![a-zA-Z0-9]))`, 'i');
    if (regex.test(normalizedText)) {
      extracted.add(canonical);
    }
  }

  return Array.from(extracted);
}

// ─── Gemini Client Backoff Call ───────────────────────────────────────────────

async function callGeminiWithRetry(model, prompt, retries = 3, delay = 500) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await model.generateContent({
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: {
          responseMimeType: "application/json"
        }
      });
      return response.response.text();
    } catch (err) {
      if (attempt === retries) throw err;
      console.warn(`[ATSController] Gemini API attempt ${attempt} failed. Retrying in ${delay}ms... Error: ${err.message}`);
      await new Promise(resolve => setTimeout(resolve, delay));
      delay *= 2.5; // exponential backoff
    }
  }
}

// ─── ATS Compatibility & Career Analytics Helpers (V2.1) ──────────────────────

function auditAtsCompatibilityAndRisk(buffer, mimeType, filename, text, isTechRole) {
  let atsCompatibilityScore = 100;
  const compatibilityIssues = [];
  const compatibilityWarnings = [];
  let atsRiskScore = 0;
  const riskFactors = [];

  const cleanMime = String(mimeType).trim().toLowerCase();
  const cleanName = String(filename).trim().toLowerCase();

  let hasTables = false;
  let hasColumns = false;
  let hasTextBoxes = false;
  let hasDrawings = false;
  let hasImages = false;
  let hasHeadersOrFooters = false;

  // 1. Scan doc buffers for layout elements
  if (cleanMime === 'application/pdf' || cleanName.endsWith('.pdf')) {
    try {
      const bufferStr = buffer.toString('binary');
      
      // High-precision images: only flag if imageCount > 2 or imageArea > 15%
      const imageMatches = bufferStr.match(/\/Subtype\s*\/Image/gi) || [];
      const imageCount = imageMatches.length;

      const widthMatches = bufferStr.match(/\/Width\s+(\d+)/gi) || [];
      const heightMatches = bufferStr.match(/\/Height\s+(\d+)/gi) || [];
      let totalImageArea = 0;
      const minLen = Math.min(widthMatches.length, heightMatches.length);
      for (let i = 0; i < minLen; i++) {
        const w = parseInt(widthMatches[i].replace(/\/Width\s+/i, ''), 10);
        const h = parseInt(heightMatches[i].replace(/\/Height\s+/i, ''), 10);
        if (!isNaN(w) && !isNaN(h)) {
          totalImageArea += w * h;
        }
      }
      const pageArea = 500000;
      const imageAreaPercent = (totalImageArea / pageArea) * 100;

      if (imageCount > 2 || imageAreaPercent > 15) {
        hasImages = true;
        compatibilityIssues.push(`Significant graphic elements detected: found ${imageCount} images (occupying approx ${Math.round(imageAreaPercent)}% page area).`);
        atsCompatibilityScore -= 10;
        atsRiskScore += 10;
        riskFactors.push('Embedded image objects');
      }

      // High-precision tables: check for more than 5 pipes '|' or boundary indicators '+---+'
      const pipeMatches = text.match(/\|/g) || [];
      const hasBoundaryIndicator = /\+---+/.test(text);
      if (pipeMatches.length > 5 || hasBoundaryIndicator) {
        hasTables = true;
        compatibilityIssues.push('Visual grid or tabular structures detected in text layout');
        atsCompatibilityScore -= 15;
        atsRiskScore += 15;
        riskFactors.push('Heavy use of tables');
      }

      // High-precision columns: check for actual columns (more than 10 wide-space gap segments)
      const wideSpaceMatches = text.match(/ {6,}/g) || [];
      if (wideSpaceMatches.length > 10) {
        hasColumns = true;
        compatibilityIssues.push('Multi-column layout structure detected in text spacing');
        atsCompatibilityScore -= 15;
        atsRiskScore += 15;
        riskFactors.push('Multi-column layout formatting');
      }
    } catch (err) {
      console.warn('[ATSController] PDF binary scan failed:', err.message);
    }
  } else if (
    cleanMime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
    cleanName.endsWith('.docx')
  ) {
    try {
      const zip = new AdmZip(buffer);
      const documentXml = zip.readAsText('word/document.xml');

      // Detect tables
      if (documentXml.includes('<w:tbl>')) {
        hasTables = true;
        compatibilityIssues.push('Tabular formatting structure (<w:tbl>) detected in DOCX XML');
        atsCompatibilityScore -= 15;
        atsRiskScore += 15;
        riskFactors.push('Heavy use of tables');
      }

      // Detect columns
      if (documentXml.includes('<w:cols')) {
        hasColumns = true;
        compatibilityIssues.push('Multi-column section tags (<w:cols>) detected in DOCX XML');
        atsCompatibilityScore -= 15;
        atsRiskScore += 15;
        riskFactors.push('Multi-column layout formatting');
      }

      // Detect textboxes
      if (documentXml.includes('<w:txbxContent>')) {
        hasTextBoxes = true;
        compatibilityIssues.push('Floating textbox containers (<w:txbxContent>) detected in DOCX XML');
        atsCompatibilityScore -= 10;
        atsRiskScore += 10;
        riskFactors.push('Text box dependency');
      }

      // Detect drawings / graphic elements
      if (documentXml.includes('<w:drawing>') || documentXml.includes('<w:pict>')) {
        hasDrawings = true;
        compatibilityIssues.push('Embedded drawings or vector graphics detected in DOCX XML');
        atsCompatibilityScore -= 10;
        atsRiskScore += 10;
        riskFactors.push('Embedded graphics / drawings');
      }

      // Check header/footer file entries
      const entries = zip.getEntries().map(e => e.entryName);
      const headerFooterEntries = entries.filter(name => name.startsWith('word/header') || name.startsWith('word/footer'));
      if (headerFooterEntries.length > 0) {
        hasHeadersOrFooters = true;
        
        // Scan header/footer contents for email/phone
        let contactInHeaderFooter = false;
        for (const entryPath of headerFooterEntries) {
          const content = zip.readAsText(entryPath);
          if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(content) || /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/.test(content)) {
            contactInHeaderFooter = true;
            break;
          }
        }

        // Check if contact details are also present in main document body
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
        const phoneRegex = /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/;
        const mainHasEmail = emailRegex.test(documentXml);
        const mainHasPhone = phoneRegex.test(documentXml);

        if (contactInHeaderFooter && (!mainHasEmail || !mainHasPhone)) {
          compatibilityIssues.push('Primary contact details are confined to headers/footers XML structure');
          atsCompatibilityScore -= 10;
          atsRiskScore += 10;
          riskFactors.push('Header/Footer dependency');
        }
      }
    } catch (err) {
      console.warn('[ATSController] DOCX XML unzip and scan failed:', err.message);
    }
  }

  // 2. Validate contact details presence
  const contactInfo = parseContactInfo(text);
  if (!contactInfo.email) {
    compatibilityIssues.push('Missing email contact details');
    atsCompatibilityScore -= 20;
    atsRiskScore += 25;
    riskFactors.push('Missing contact information (Email)');
  }
  if (!contactInfo.phone) {
    compatibilityIssues.push('Missing phone number contact details');
    atsCompatibilityScore -= 15;
    atsRiskScore += 20;
    riskFactors.push('Missing contact information (Phone)');
  }
  if (!contactInfo.linkedin) {
    compatibilityWarnings.push('Missing LinkedIn profile reference link');
    atsCompatibilityScore -= 10;
    atsRiskScore += 15;
    riskFactors.push('Missing contact information (LinkedIn)');
  }
  if (isTechRole && !contactInfo.github) {
    compatibilityWarnings.push('Missing GitHub repository reference (strongly recommended for technical candidates)');
    atsCompatibilityScore -= 10;
    atsRiskScore += 10;
    riskFactors.push('Missing GitHub reference');
  }

  // 3. Word count sanity checks
  const wordCount = text.split(/\s+/).filter(Boolean).length;
  if (wordCount < 200) {
    compatibilityIssues.push('Critically short resume (under 200 words)');
    atsCompatibilityScore -= 15;
    atsRiskScore += 15;
    riskFactors.push('Very short resume');
  } else if (wordCount > 1500) {
    compatibilityIssues.push('Excessively long resume (exceeds 1500 words limit)');
    atsCompatibilityScore -= 15;
    atsRiskScore += 15;
    riskFactors.push('Very long resume');
  }

  // 4. Keyword stuffing / repeated keywords checks
  const wordsList = text
    .toLowerCase()
    .replace(/[^\w\s-]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 3 && !STOP_WORDS.has(w) && !/^\d+$/.test(w));
  const counts = {};
  let stuffedKw = null;
  for (const w of wordsList) {
    counts[w] = (counts[w] || 0) + 1;
    if (counts[w] > 10) {
      stuffedKw = w;
    }
  }
  if (stuffedKw) {
    compatibilityIssues.push(`Keyword stuffing detected: term "${stuffedKw}" is repeated ${counts[stuffedKw]} times`);
    atsCompatibilityScore -= 10;
    atsRiskScore += 15;
    riskFactors.push('Keyword stuffing / repetition detected');
  }

  // Clamp results
  atsCompatibilityScore = Math.max(0, Math.min(100, atsCompatibilityScore));
  atsRiskScore = Math.max(0, Math.min(100, atsRiskScore));

  return {
    atsCompatibilityScore,
    compatibilityIssues,
    compatibilityWarnings,
    atsRiskScore,
    riskFactors
  };
}

function detectCareerLevel(years, text, roleTitle) {
  const cleanTitle = String(roleTitle || '').toLowerCase();
  const cleanText = String(text || '').toLowerCase();

  // 1. Check title/text keywords for Director
  if (
    cleanTitle.includes('director') || 
    cleanTitle.includes('vp') || 
    cleanTitle.includes('vice president') || 
    cleanTitle.includes('head of') || 
    (years >= 10 && (cleanText.includes('director of') || cleanText.includes('vice president')))
  ) {
    return 'Director';
  }

  // 2. Check title/text keywords for Lead / Manager
  if (cleanTitle.includes('manager') || cleanText.includes('project manager') || cleanText.includes('product manager')) {
    if (years >= 8) return 'Manager';
  }

  if (
    cleanTitle.includes('lead') || 
    cleanTitle.includes('architect') || 
    cleanTitle.includes('principal') ||
    cleanText.includes('team owner') ||
    cleanText.includes('managed a team') ||
    cleanText.includes('leadership responsibility') ||
    (years >= 8 && (cleanTitle.includes('manager') || cleanTitle.includes('lead') || cleanText.includes('team lead')))
  ) {
    return 'Lead';
  }

  // 3. Map purely by years if no explicit leadership matches
  if (years < 1 || cleanTitle.includes('intern') || cleanText.includes('student developer')) {
    return 'Intern';
  }
  if (years <= 2) {
    return 'Junior';
  }
  if (years <= 3) {
    return 'Associate';
  }
  if (years <= 5) {
    return 'Mid-Level';
  }
  if (years <= 8) {
    return 'Senior';
  }

  return 'Senior';
}

function analyzeCareerProgression(experienceText) {
  const lines = experienceText.split(/\n+/).map(l => l.trim()).filter(l => l.length > 10);
  const roleLevels = [];

  for (const line of lines) {
    const lowerLine = line.toLowerCase();
    let level = 0;

    if (lowerLine.includes('director') || lowerLine.includes('vp') || lowerLine.includes('vice president') || lowerLine.includes('head of')) {
      level = 5;
    } else if (lowerLine.includes('lead') || lowerLine.includes('manager') || lowerLine.includes('architect') || lowerLine.includes('principal')) {
      level = 4;
    } else if (lowerLine.includes('senior') || lowerLine.includes('sr.')) {
      level = 3;
    } else if (lowerLine.includes('engineer') || lowerLine.includes('developer') || lowerLine.includes('analyst') || lowerLine.includes('associate') || lowerLine.includes('consultant')) {
      level = 2;
    } else if (lowerLine.includes('intern') || lowerLine.includes('trainee') || lowerLine.includes('co-op')) {
      level = 1;
    }

    if (level > 0) {
      const yearMatch = lowerLine.match(/\b(19|20\d{2})\b/);
      const year = yearMatch ? parseInt(yearMatch[1], 10) : 0;
      roleLevels.push({ level, hasYear: !!yearMatch, year, line });
    }
  }

  const cleanRoles = roleLevels.filter(r => r.hasYear);
  // Sort by year descending to ensure reverse chronological order (latest first)
  cleanRoles.sort((a, b) => b.year - a.year);

  const finalRoles = cleanRoles.length >= 2 ? cleanRoles : roleLevels;

  if (finalRoles.length < 2) {
    return {
      careerProgressionScore: 100,
      careerProgression: "Stable career timeline with consistent role level progression."
    };
  }

  let demotions = 0;
  for (let i = 0; i < finalRoles.length - 1; i++) {
    // Reverse chronological matching
    if (finalRoles[i].level < finalRoles[i + 1].level) {
      demotions++;
    }
  }

  let careerProgressionScore = 100;
  let careerProgression = "Chronological role progression indicates solid upward mobility and career growth.";

  if (demotions > 0) {
    careerProgressionScore = Math.max(40, 100 - demotions * 30);
    careerProgression = "Potential career level inconsistency detected: candidate held a higher-ranking role in the past compared to a subsequent position in their timeline.";
  }

  return { careerProgressionScore, careerProgression };
}

// ─── Controller Methods ────────────────────────────────────────────────────────

async function analyzeResume(req, res, next) {
  try {
    const { jdText, jdTitle } = req.body;
    let pastedJdText = jdText || '';
    let processedJdTitle = jdTitle || 'Job Description Requirement';

    // 1. Resolve Job Description (Paste or Upload file)
    if (req.files && req.files.jdFile) {
      const jdFileObj = req.files.jdFile[0];
      pastedJdText = await extractTextFromBuffer(jdFileObj.buffer, jdFileObj.mimetype, jdFileObj.originalname);
      processedJdTitle = jdFileObj.originalname.replace(/\.[^/.]+$/, "");
    }

    if (!pastedJdText.trim()) {
      return res.status(400).json({ error: 'Job description text or file is required' });
    }

    // 2. Resolve Resume File
    if (!req.files || !req.files.resumeFile) {
      return res.status(400).json({ error: 'Resume file is required' });
    }
    const resumeFileObj = req.files.resumeFile[0];
    const resumeText = await extractTextFromBuffer(resumeFileObj.buffer, resumeFileObj.mimetype, resumeFileObj.originalname);

    if (!resumeText.trim()) {
      return res.status(400).json({ error: 'Failed to extract text from the resume file' });
    }

    // ─── Phase 2: SHA256 Caching Check ───────────────────────────────────────────
    const cacheKey = crypto.createHash('sha256').update(resumeText + pastedJdText).digest('hex');
    const cachedReport = await ATSReport.findOne({ cacheKey })
      .populate('resumeId', 'fileName metadata')
      .populate('jobDescriptionId', 'title');

    if (cachedReport) {
      await logEvent({
        action: 'ats-report-generated',
        entityType: 'Content',
        entityId: cachedReport._id,
        performedBy: req.user.userId,
        details: { resumeFile: cachedReport.resumeId?.fileName, jdTitle: cachedReport.jobDescriptionId?.title, score: cachedReport.scores.consensusScore, cached: true }
      });

      return res.status(201).json({
        reportId: cachedReport._id,
        scores: cachedReport.scores,
        analysis: cachedReport.analysis,
        reportMarkdown: cachedReport.reportMarkdown
      });
    }

    // ─── Phase 3: Local Entity Extraction ────────────────────────────────────────
    const dbSkills = await SkillKnowledgeBase.find({});
    const skillLookup = new Map();
    for (const s of dbSkills) {
      const canon = s.canonicalName.toLowerCase();
      skillLookup.set(canon, canon);
      if (s.aliases) {
        for (const alias of s.aliases) {
          skillLookup.set(alias.toLowerCase(), canon);
        }
      }
    }

    const localResumeSkills = extractLocalEntities(resumeText, skillLookup);
    const localJdSkills = extractLocalEntities(pastedJdText, skillLookup);

    // Save parsed raw texts in DB
    const jobDescription = await ATSJobDescription.create({
      title: processedJdTitle,
      rawText: pastedJdText,
      skills: localJdSkills,
      keywords: extractKeywords(pastedJdText, 25),
      owner: req.user.userId
    });

    const contactInfo = parseContactInfo(resumeText);
    const resumeSections = extractSections(resumeText);

    // Structure found headings mapping
    const structureFound = [];
    if (resumeSections['EXPERIENCE'] || resumeSections['WORK EXPERIENCE'] || resumeSections['PROFESSIONAL EXPERIENCE'] || resumeSections['EMPLOYMENT']) {
      structureFound.push('experience');
    }
    if (resumeSections['EDUCATION'] || resumeSections['ACADEMIC BACKGROUND']) {
      structureFound.push('education');
    }
    if (resumeSections['SKILLS']) {
      structureFound.push('skills');
    }
    if (resumeSections['PROJECTS'] || resumeSections['PERSONAL PROJECTS'] || resumeSections['KEY PROJECTS'] || resumeSections['ACADEMIC PROJECTS']) {
      structureFound.push('projects');
    }

    const resume = await ATSResume.create({
      fileName: resumeFileObj.originalname,
      rawText: resumeText,
      metadata: {
        email: contactInfo.email,
        phone: contactInfo.phone,
        links: [contactInfo.linkedin, contactInfo.github].filter(Boolean),
        sectionsFound: structureFound
      },
      owner: req.user.userId
    });

    // ─── Phase 4 & 5 & 8 & 11: Gemini Recruiter Simulation & Validation ───────────
    let geminiAtsResult = null;
    let validatedResumeSkills = localResumeSkills;
    let validatedJdSkills = localJdSkills;
    let criticalSkills = [];
    let requiredSkills = localJdSkills;
    let preferredSkills = [];
    let jdResponsibilities = [];
    let requiredExperience = 2;
    let detectedRole = 'Software Engineer';
    let roleConfidence = 50;
    let careerLevel = 'Junior';
    let semanticScore = 50;
    let strengths = [];
    let weaknesses = [];
    let reasoning = 'Semantic match evaluated using local cosine fallback index.';
    let hiringRecommendation = 'Consider';
    let interviewProbability = 40;

    // Detect if tech role to trigger GitHub risk checks
    const isTechRole = localJdSkills.length > 2 || localResumeSkills.length > 2;

    if (process.env.NODE_ENV !== 'test' && process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'DUMMY_KEY') {
      try {
        const { GoogleGenerativeAI } = require('@google/generative-ai');
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

        const prompt = `
You are a senior recruiter with 15 years of hiring experience.

Analyze the candidate's resume relative to the Job Description:
Resume: "${resumeText.slice(0, 15000)}"
Job Description: "${pastedJdText.slice(0, 15000)}"
Locally Extracted Resume Skills: [${localResumeSkills.join(', ')}]
Locally Extracted JD Skills: [${localJdSkills.join(', ')}]

Evaluate:
1. Technical Skill Alignment (Confirm, prune or expand locally extracted skills)
2. Classify Job Description skills dynamically into:
   - Critical Skills (must-have core requirements)
   - Required Skills (standard requirements for the role)
   - Preferred Skills (nice-to-have or secondary skills)
3. Extract core responsibilities/operational tasks expected in the job description (as separate sentences or concise statements).
4. Experience Alignment (Estimate required years of experience from JD)
5. Project Relevance
6. Industry Relevance
7. Seniority Alignment (Map career level)
8. Leadership Indicators & Potential
9. Communication Quality & Resume Professionalism

Return strict JSON only:
{
  "role": "<Detected Job Role, e.g. Frontend Developer>",
  "roleConfidence": <Number 0-100>,
  "careerLevel": "<Intern | Junior | Associate | Mid-Level | Senior | Lead | Manager | Director>",
  "criticalSkills": [<Core must-have technical skills from the JD>],
  "requiredSkills": [<Expected technical skills from the JD>],
  "preferredSkills": [<Nice-to-have or preferred technical skills from the JD>],
  "jdResponsibilities": [<Concise list of responsibilities/tasks extracted from the JD>],
  "requiredExperience": <Number of years required by the JD, default to 2 if not stated>,
  "validatedResumeSkills": [<Pruned list of actual skills in the resume>],
  "validatedJdSkills": [<Pruned list of actual skills in the JD>],
  "semanticScore": <Score 0-100 based on overall suitability>,
  "strengths": [<Array of strengths>],
  "weaknesses": [<Array of weaknesses>],
  "reasoning": "<Recruiter evaluation summary>",
  "hiringRecommendation": "<Reject | Consider | Shortlist | Strong Shortlist>",
  "interviewProbability": <Number 0-100 indicating likelihood of landing interview>
}
`;

        const responseText = await callGeminiWithRetry(model, prompt);
        geminiAtsResult = JSON.parse(responseText.trim());

        if (geminiAtsResult) {
          detectedRole = geminiAtsResult.role || detectedRole;
          roleConfidence = geminiAtsResult.roleConfidence || roleConfidence;
          careerLevel = geminiAtsResult.careerLevel || careerLevel;
          criticalSkills = geminiAtsResult.criticalSkills || criticalSkills;
          requiredSkills = geminiAtsResult.requiredSkills || requiredSkills;
          preferredSkills = geminiAtsResult.preferredSkills || preferredSkills;
          jdResponsibilities = geminiAtsResult.jdResponsibilities || jdResponsibilities;
          requiredExperience = geminiAtsResult.requiredExperience !== undefined ? geminiAtsResult.requiredExperience : requiredExperience;
          validatedResumeSkills = geminiAtsResult.validatedResumeSkills || validatedResumeSkills;
          validatedJdSkills = geminiAtsResult.validatedJdSkills || validatedJdSkills;
          semanticScore = geminiAtsResult.semanticScore || semanticScore;
          strengths = geminiAtsResult.strengths || strengths;
          weaknesses = geminiAtsResult.weaknesses || weaknesses;
          reasoning = geminiAtsResult.reasoning || reasoning;
          hiringRecommendation = geminiAtsResult.hiringRecommendation || hiringRecommendation;
          interviewProbability = geminiAtsResult.interviewProbability || interviewProbability;
        }
      } catch (err) {
        console.warn('[ATSController] Gemini API call failed. Using local heuristic fallback:', err.message);
      }
    }

    // Local Fallback if Gemini failed or is not configured
    if (!geminiAtsResult) {
      // 1. Detect role from JD title or keywords
      const titleLower = processedJdTitle.toLowerCase();
      if (titleLower.includes('frontend') || titleLower.includes('react')) detectedRole = 'Frontend Developer';
      else if (titleLower.includes('backend') || titleLower.includes('node')) detectedRole = 'Backend Developer';
      else if (titleLower.includes('devops') || titleLower.includes('cloud')) detectedRole = 'DevOps Engineer';
      else if (titleLower.includes('data')) detectedRole = 'Data Scientist';
      else if (titleLower.includes('product')) detectedRole = 'Product Manager';
      else if (titleLower.includes('marketing')) detectedRole = 'Marketing Manager';
      
      // 2. Local semantic score
      const localSemanticRes = await computeSemanticSimilarity(resumeText, pastedJdText);
      semanticScore = Math.round(localSemanticRes.cosine_score * 100);
      reasoning = `Local Semantic Evaluation: ${localSemanticRes.explanation}`;

      // 3. Fallback required experience from JD
      const experienceRegex = /\b(\d+)\s*\+?\s*(?:year|yr|yr\.)/i;
      const expMatch = pastedJdText.match(experienceRegex);
      if (expMatch) {
        requiredExperience = parseInt(expMatch[1], 10);
      }

      // 4. Dynamic skill classification boundary by popularityScore
      const skillPopularityMap = new Map();
      for (const s of dbSkills) {
        skillPopularityMap.set(s.canonicalName.toLowerCase(), s.popularityScore || 50);
      }
      
      criticalSkills = [];
      requiredSkills = [];
      preferredSkills = [];
      for (const skill of validatedJdSkills) {
        const pop = skillPopularityMap.get(skill.toLowerCase()) || 50;
        if (pop >= 90) {
          criticalSkills.push(skill);
        } else if (pop >= 60) {
          requiredSkills.push(skill);
        } else {
          preferredSkills.push(skill);
        }
      }

      // 5. Responsibilities heuristic
      jdResponsibilities = extractJdResponsibilitiesHeuristic(pastedJdText);

      // 6. Strengths & Weaknesses fallback
      strengths.push('Matches core keywords in job description.');
      if (localResumeSkills.length > 5) strengths.push('Demonstrates solid technology usage breadth.');
      if (localJdSkills.filter(s => !localResumeSkills.includes(s)).length > 3) {
        weaknesses.push('Lacks multiple required domain skills.');
      }
      
      // 7. Hiring recommendation fallback
      hiringRecommendation = semanticScore >= 80 ? 'Strong Shortlist' : semanticScore >= 65 ? 'Shortlist' : semanticScore >= 45 ? 'Consider' : 'Reject';
      interviewProbability = Math.round(semanticScore * 0.95);
    }

    // ─── Phase 6: Skill Match Engine (Weighted Coverage) ───────────────────────
    const matchedSkills = validatedResumeSkills.filter(s => validatedJdSkills.includes(s));
    const missingSkills = validatedJdSkills.filter(s => !validatedResumeSkills.includes(s));
    const extraSkills = validatedResumeSkills.filter(s => !validatedJdSkills.includes(s));

    let matchedWeight = 0;
    let totalWeight = 0;

    for (const skill of validatedJdSkills) {
      let weight = 1; // Preferred
      if (criticalSkills.includes(skill)) {
        weight = 3;
      } else if (requiredSkills.includes(skill)) {
        weight = 2;
      }
      
      totalWeight += weight;
      if (matchedSkills.includes(skill)) {
        matchedWeight += weight;
      }
    }

    const weightedSkillCoverage = totalWeight > 0 ? Math.round((matchedWeight / totalWeight) * 100) : 100;

    // Synonym-aware responsibility matching
    const matchedResponsibilities = [];
    const missingResponsibilities = [];

    if (jdResponsibilities.length === 0) {
      jdResponsibilities = extractJdResponsibilitiesHeuristic(pastedJdText);
    }
    
    for (const resp of jdResponsibilities) {
      if (matchResponsibility(resumeText, resp)) {
        matchedResponsibilities.push(resp);
      } else {
        missingResponsibilities.push(resp);
      }
    }

    const responsibilityCoverage = jdResponsibilities.length > 0
      ? Math.round((matchedResponsibilities.length / jdResponsibilities.length) * 100)
      : 100;

    // Extract matched and missing keywords for the frontend
    const jdKeywords = jobDescription.keywords || [];
    const resumeLowerForKw = resumeText.toLowerCase();
    const matchedKeywords = [];
    const missingKeywords = [];

    for (const kw of jdKeywords) {
      const lowerKw = kw.toLowerCase();
      let isMatch = resumeLowerForKw.includes(lowerKw);
      if (!isMatch) {
        const synGroup = SYNONYM_GROUPS.find(group => group.includes(lowerKw));
        if (synGroup) {
          isMatch = synGroup.some(syn => resumeLowerForKw.includes(syn));
        }
      }
      if (isMatch) {
        matchedKeywords.push(kw);
      } else {
        missingKeywords.push(kw);
      }
    }

    // ─── Phase 7: Experience Engine & Career Level ──────────────────────────────
    const yearsOfExperience = parseExperienceYears(resumeSections);
    const candidateType = yearsOfExperience > 0 ? 'experienced' : 'fresher';

    careerLevel = detectCareerLevel(yearsOfExperience, resumeText, detectedRole);

    const experienceAlignment = yearsOfExperience >= requiredExperience 
      ? 100 
      : Math.round((yearsOfExperience / requiredExperience) * 100);

    // JD Coverage Score
    const jdCoverageScore = Math.round(
      (weightedSkillCoverage * 0.50) +
      (responsibilityCoverage * 0.30) +
      (experienceAlignment * 0.20)
    );

    // ─── Phase 8: ATS Risk Engine, Compatibility & Layout Audit ──────────────────
    const compatibilityAudit = auditAtsCompatibilityAndRisk(
      resumeFileObj.buffer,
      resumeFileObj.mimetype,
      resumeFileObj.originalname,
      resumeText,
      isTechRole
    );
    const {
      atsCompatibilityScore,
      compatibilityIssues,
      compatibilityWarnings,
      atsRiskScore,
      riskFactors
    } = compatibilityAudit;

    const structureIssues = [...compatibilityIssues];
    if (!structureFound.includes('experience')) {
      structureIssues.push('Missing standard "Experience" section header.');
    }
    if (!structureFound.includes('skills')) {
      structureIssues.push('Missing standard "Skills" section header.');
    }
    if (!structureFound.includes('education')) {
      structureIssues.push('Missing standard "Education" section header.');
    }

    // ─── Phase 9: Structure Score ───────────────────────────────────────────────
    let structureScore = 40; // Base score
    structureScore += structureFound.length * 10; // Up to 40 points for sections
    
    // Check for bullets
    if (/[\u2022\u2023\u25E6\u2043\u2219\-*▪]/g.test(resumeText)) {
      structureScore += 10;
    }
    // Check for quantified metrics
    if (/(\d+%|\$\d+|\b\d+\s+(?:percent|users|dollars|hours|months|records)\b)/gi.test(resumeText)) {
      structureScore += 10;
    }

    structureScore = Math.min(structureScore, 100);

    // ─── Phase 10: Recruiter Readiness Engine ───────────────────────────────────
    const verbsFound = extractActionVerbs(resumeText);
    
    // Check for metrics count
    const metricsMatches = resumeText.match(/(\d+%|\$\d+(?:,\d{3})*(?:\.\d{2})?[kMB]?|\b\d+\s+(?:percent|users|dollars|hours|months|days|records)\b)/gi) || [];
    const achievementsCount = metricsMatches.length;

    let recruiterScore = 30; // base score
    recruiterScore += Math.min(verbsFound.length * 7, 35); // action verbs
    recruiterScore += Math.min(achievementsCount * 8, 35); // business impact metrics
    
    recruiterScore = Math.min(recruiterScore, 100);

    // ─── Phase 11: Career Progression Analysis ───────────────────────────────────
    const experienceKeys = ['EXPERIENCE', 'WORK EXPERIENCE', 'PROFESSIONAL EXPERIENCE', 'EMPLOYMENT'];
    let experienceText = '';
    for (const key of experienceKeys) {
      if (resumeSections[key]) {
        experienceText += '\n' + resumeSections[key];
      }
    }
    const { careerProgressionScore, careerProgression } = analyzeCareerProgression(experienceText);

    // ─── Phase 12: Final ATS Score (Consensus Score) ─────────────────────────────
    // weights: skillScore 35%, responsibilityCoverage 20%, experienceScore 15%, qualityScore 10%, recruiterScore 5%, semanticScore 10%, atsCompatibilityScore 5%
    const atsScore = Math.round(
      (weightedSkillCoverage * 0.35) +
      (responsibilityCoverage * 0.20) +
      (experienceAlignment * 0.15) +
      (structureScore * 0.10) +
      (recruiterScore * 0.05) +
      (semanticScore * 0.10) +
      (atsCompatibilityScore * 0.05)
    );

    const consensusScore = Math.max(0, Math.min(atsScore, 100));

    // Recruiter Confidence Engine v2
    const matchedCritical = criticalSkills.filter(s => validatedResumeSkills.includes(s));
    const criticalSkillCoverage = criticalSkills.length > 0 ? (matchedCritical.length / criticalSkills.length) * 100 : 100;
    const matchedRequired = requiredSkills.filter(s => validatedResumeSkills.includes(s));
    const requiredSkillCoverage = requiredSkills.length > 0 ? (matchedRequired.length / requiredSkills.length) * 100 : 100;

    const skillConfidence = (criticalSkillCoverage * 0.60) + (requiredSkillCoverage * 0.40);
    const semanticConfidence = semanticScore;
    const experienceConfidence = (experienceAlignment * 0.70) + (careerProgressionScore * 0.30);
    const structureConfidence = (atsCompatibilityScore * 0.60) + (structureScore * 0.40);

    let recruiterConfidence = Math.round(
      (skillConfidence * 0.35) +
      (semanticConfidence * 0.30) +
      (experienceConfidence * 0.20) +
      (structureConfidence * 0.15)
    );
    recruiterConfidence = Math.max(0, Math.min(100, recruiterConfidence));

    // Recommendation bands & Override Logic
    let baseRecommendation = 'Reject';
    if (consensusScore >= 90) baseRecommendation = 'Strong Shortlist';
    else if (consensusScore >= 75) baseRecommendation = 'Shortlist';
    else if (consensusScore >= 60) baseRecommendation = 'Consider';

    // Override logic: Demote by 1 step if Critical coverage < 40% or Experience alignment < 50%
    if (criticalSkillCoverage < 40 || experienceAlignment < 50) {
      if (baseRecommendation === 'Strong Shortlist') hiringRecommendation = 'Shortlist';
      else if (baseRecommendation === 'Shortlist') hiringRecommendation = 'Consider';
      else hiringRecommendation = 'Reject';
    } else {
      hiringRecommendation = baseRecommendation;
    }

    // ─── Phase 13: Database Percentile Benchmarking ──────────────────────────────
    const totalRoleReports = await ATSReport.countDocuments({ "analysis.role": detectedRole });
    const lowerRoleReports = await ATSReport.countDocuments({ 
      "analysis.role": detectedRole, 
      "scores.consensusScore": { $lte: consensusScore } 
    });
    
    const roleDatasetSize = totalRoleReports + 1;
    const rankPosition = roleDatasetSize - lowerRoleReports;

    let benchmarkReliability = 'Low';
    if (roleDatasetSize >= 1000) benchmarkReliability = 'High';
    else if (roleDatasetSize >= 250) benchmarkReliability = 'Medium';

    let percentile = 100;
    if (totalRoleReports > 0) {
      percentile = Math.round((lowerRoleReports / totalRoleReports) * 100);
    }

    let benchmarkRank = 'Below Average';
    if (roleDatasetSize < 100) {
      benchmarkRank = `Rank ${rankPosition} of ${roleDatasetSize}`;
    } else {
      if (percentile >= 90) benchmarkRank = 'Top 10%';
      else if (percentile >= 75) benchmarkRank = 'Top 25%';
      else if (percentile >= 50) benchmarkRank = 'Top 50%';
    }

    // ─── Phase 14: Version Comparison & Tracking (Progress Tracker) ──────────────
    const matchingJds = await ATSJobDescription.find({ title: processedJdTitle }).select('_id');
    const jdIds = matchingJds.map(jd => jd._id);
    const previousReport = await ATSReport.findOne({
      owner: req.user.userId,
      jobDescriptionId: { $in: jdIds }
    }).sort({ createdAt: -1 });

    let previousScore = 0;
    let improvement = 0;
    let newSkillsAdded = [];
    let resolvedIssues = [];
    let newIssues = [];

    if (previousReport) {
      previousScore = previousReport.scores.consensusScore || 0;
      improvement = consensusScore - previousScore;
      
      const prevSkills = previousReport.analysis.resumeSkills || [];
      newSkillsAdded = validatedResumeSkills.filter(s => !prevSkills.includes(s));

      const prevIssues = previousReport.analysis.structureIssues || [];
      const currentIssues = structureIssues || [];
      resolvedIssues = prevIssues.filter(iss => !currentIssues.includes(iss));
      newIssues = currentIssues.filter(iss => !prevIssues.includes(iss));
    }

    // ─── Phase 15: Learning Roadmap Generation ───────────────────────────────────
    // Priority 1: Missing Required Skills
    const priority1 = missingSkills.filter(s => requiredSkills.includes(s));
    
    // Priority 2: Missing Preferred Skills
    const priority2 = missingSkills.filter(s => preferredSkills.includes(s) && !priority1.includes(s));

    // Priority 3: Related/Recommended Skills
    const priority3Set = new Set();
    for (const skill of matchedSkills) {
      const matchDb = dbSkills.find(s => s.canonicalName === skill);
      if (matchDb && matchDb.relatedSkills) {
        for (const rel of matchDb.relatedSkills) {
          if (!validatedResumeSkills.includes(rel)) {
            priority3Set.add(rel);
          }
        }
      }
    }
    const priority3 = Array.from(priority3Set).slice(0, 5);

    const learningRoadmap = {
      priority1,
      priority2,
      priority3
    };

    // Recruiter Suggestions Compilation
    const finalSuggestions = [];
    if (structureIssues.length > 0) {
      structureIssues.forEach(issue => finalSuggestions.push(issue));
    }
    if (priority1.length > 0) {
      finalSuggestions.push(`Acquire high-priority missing technical skill required for this role: ${priority1.slice(0, 3).map(s => `*${s}*`).join(', ')}.`);
    }
    if (yearsOfExperience < requiredExperience) {
      finalSuggestions.push(`JD requests **${requiredExperience}** years of experience. Highlight relevant internships, freelance work, or side projects to align with seniority expectations.`);
    }
    if (achievementsCount < 3) {
      finalSuggestions.push('Quantify your experience. Add numerical results (e.g., *optimized loading speeds by 40%*, *supported a client base of 2,000+*) to demonstrate impact.');
    }

    // Detailed keyword breakdowns for schema
    const matchedTechSkills = matchedSkills;
    const missingTechSkills = missingSkills;
    const matchedRespKeywords = matchedKeywords.filter(kw => getKeywordWeight(kw) === 2);
    const missingRespKeywords = missingKeywords.filter(kw => getKeywordWeight(kw) === 2);
    const matchedVerbs = matchedKeywords.filter(kw => getKeywordWeight(kw) === 1);
    const missingVerbs = missingKeywords.filter(kw => getKeywordWeight(kw) === 1);

    // ─── Report Markdown Generation (7 Sections) ─────────────────────────────────
    const reportMarkdown = `
# ATS Resume Intelligence Report

## 1. Executive Summary
This report details the forensic parsing and compatibility analysis of the candidate's resume (\`${resume.fileName}\`) against the requirements outlined in the Job Description (\`${jobDescription.title}\`). Using multiple parser heuristic layers, layout auditors, and conceptual semantic embeddings, the system computed an overall **Consensus Compatibility Score of ${consensusScore}%**.

## 2. Risk Level
- **ATS Compatibility / Rejection Risk**: **${consensusScore >= 80 ? 'LOW (Optimized)' : consensusScore >= 60 ? 'MEDIUM (Caution)' : 'HIGH (Review Required)'}**
- **Consensus Compatibility Score**: **${consensusScore}%**
- **JD Coverage Score**: **${jdCoverageScore}%**
- **Recruiter Confidence**: **${recruiterConfidence}%**
- **Benchmark Rank**: **${benchmarkRank}** (Standing at the ${percentile}th percentile among all evaluated ${detectedRole} applicants, Benchmark Reliability: ${benchmarkReliability})

## 3. Findings
- **Weighted Skill Coverage**: **${weightedSkillCoverage}%**
- **Technical Skill Alignment**: **${weightedSkillCoverage}%**
- **Structure Formatting Audit**: **${structureScore}%**
- **Recruiter Readiness Index**: **${recruiterScore}%**
- **Semantic Match Score**: **${semanticScore}%**
- **ATS Compatibility Score**: **${atsCompatibilityScore}%**
- **Career Progression Score**: **${careerProgressionScore}%**
- **Responsibility Coverage**: **${responsibilityCoverage}%**

### Parsed Resume Metrics:
- **Detected Role**: **${detectedRole}** (${roleConfidence}% Confidence)
- **Career Seniority Level**: **${careerLevel.toUpperCase()}**
- **Measurable Achievements Found**: ${achievementsCount} metrics
- **Strong Action Verbs Found**: ${verbsFound.length} verbs
- **Chronological Experience Parsed**: ${yearsOfExperience} estimated years
- **Layout Sections Found**: ${structureFound.join(', ').toUpperCase() || 'None'}

## 4. Raw Metrics
| Evaluation Layer | Score | Weight | Model/Library Used |
| :--- | :---: | :---: | :--- |
| Weighted Skill Match | ${weightedSkillCoverage}% | 35% | Skill Dictionary Normalizer & Gemini |
| Responsibility Coverage | ${responsibilityCoverage}% | 20% | Synonym-Aware Responsibility Engine |
| Experience Alignment | ${experienceAlignment}% | 15% | Section-Aware Date Parser |
| Layout & Chronology | ${structureScore}% | 10% | Section Header layout index |
| Recruiter Readiness | ${recruiterScore}% | 5% | Performance Verb and Metrics Density checker |
| Semantic Match | ${semanticScore}% | 10% | Google Gemini API / 16-D Semantic Fallback |
| ATS Compatibility | ${atsCompatibilityScore}% | 5% | Layout Health & Contact Info Audit |

## 5. Visual Evidence
### Hiring & ATS Analysis Summary
- **Hiring Recommendation**: **${hiringRecommendation}**
- **Interview Landing Probability**: **${interviewProbability}%**
- **Recruiter Feedback**: ${reasoning}

### Skill Weight Breakdown
*   **Critical Skills (Weight 3)**: ${criticalSkills.map(s => `\`${s}\` (${matchedSkills.includes(s) ? '✅ Matched' : '❌ Missing'})`).join(', ') || 'None'}
*   **Required Skills (Weight 2)**: ${requiredSkills.map(s => `\`${s}\` (${matchedSkills.includes(s) ? '✅ Matched' : '❌ Missing'})`).join(', ') || 'None'}
*   **Preferred Skills (Weight 1)**: ${preferredSkills.map(s => `\`${s}\` (${matchedSkills.includes(s) ? '✅ Matched' : '❌ Missing'})`).join(', ') || 'None'}

### Missing Skills & Competencies
| Required Skill / Competency | Weight | Status | Recommendation |
| :--- | :---: | :---: | :--- |
${validatedJdSkills.slice(0, 10).map(s => {
  const matched = matchedSkills.includes(s);
  const isReq = requiredSkills.includes(s);
  const isCrit = criticalSkills.includes(s);
  const weightLabel = isCrit ? 'Critical (3)' : isReq ? 'Required (2)' : 'Preferred (1)';
  return `| \`${s}\` | ${weightLabel} | ${matched ? '✅ Matched' : '❌ Missing'} | ${matched ? 'Already in resume.' : 'Insert contextually in experience bullet points.'} |`;
}).join('\n') || '| *No skills found in JD* | - | - | - |'}

### Actionable Learning Roadmap
*   **Priority 1 (Missing Required)**: ${priority1.length > 0 ? priority1.map(s => `\`${s}\``).join(', ') : 'None'}
*   **Priority 2 (Missing Preferred)**: ${priority2.length > 0 ? priority2.map(s => `\`${s}\``).join(', ') : 'None'}
*   **Priority 3 (Related Skills)**: ${priority3.length > 0 ? priority3.map(s => `\`${s}\``).join(', ') : 'None'}

### Recruiter Suggestions
${finalSuggestions.map(s => `*   ${s}`).join('\n') || '*Resume is highly optimized for this role!*'}

### Resume Progression (Version Tracker)
- **Previous Score**: ${previousScore}%
- **Current Score**: ${consensusScore}%
- **Improvement Delta**: ${improvement >= 0 ? `+${improvement}` : improvement}%
- **New Skills Added**: ${newSkillsAdded.length > 0 ? newSkillsAdded.map(s => `\`${s}\``).join(', ') : 'None'}
- **Resolved Issues**: ${resolvedIssues.length > 0 ? resolvedIssues.map(s => `\`${s}\``).join(', ') : 'None'}
- **New Issues**: ${newIssues.length > 0 ? newIssues.map(s => `\`${s}\``).join(', ') : 'None'}

## 6. Explanation
- **Semantic Match Analysis**: ${reasoning}
- **Experience Chronology Audit**: The chronological parser segments experience sections from training/projects, detecting **${yearsOfExperience} years of experience** from dates in the experience headers.
- **Career Progression Analysis**: ${careerProgression}
- **Recruiter visual alignment**: The resume scored **${recruiterScore}%** for recruiter visual/metrics scan, indicating the density of action verbs and quantifiable business impact metrics.

## 7. Confidence
- **Model Confidence**: 95%
- **Reasoning**: Evaluated using dynamic SkillKnowledgeBase normalization matching, local date section filters, and official Google Gemini API validations.
`;

    // Save final report document
    const report = await ATSReport.create({
      resumeId: resume._id,
      jobDescriptionId: jobDescription._id,
      cacheKey,
      scores: {
        consensusScore,
        keywordScore: evaluateKeywordMatch(resumeText, jobDescription.keywords),
        skillScore: weightedSkillCoverage,
        qualityScore: structureScore,
        recruiterScore,
        semanticScore,
        experienceScore: experienceAlignment,
        atsRiskScore,
        interviewProbability,
        atsCompatibilityScore,
        careerProgressionScore,
        responsibilityCoverage,
        jdCoverageScore
      },
      analysis: {
        role: detectedRole,
        candidateType,
        yearsOfExperience,
        careerLevel,
        resumeSkills: validatedResumeSkills,
        jdSkills: validatedJdSkills,
        matchedSkills,
        missingSkills,
        extraSkills,
        matchedKeywords,
        missingKeywords,
        requiredSkills,
        preferredSkills,
        learningRoadmap,
        benchmarkRank,
        strengths,
        weaknesses,
        structureIssues,
        compatibilityIssues,
        compatibilityWarnings,
        riskFactors,
        careerProgression,
        resumeProgress: {
          previousScore,
          currentScore: consensusScore,
          improvement,
          newSkillsAdded,
          resolvedIssues,
          newIssues
        },
        recommendations: finalSuggestions,
        recruiterRecommendation: hiringRecommendation,
        semanticReasoning: reasoning,
        achievementsCount,
        actionVerbsUsed: verbsFound,
        matchedTechSkills,
        missingTechSkills,
        matchedRespKeywords,
        missingRespKeywords,
        matchedVerbs,
        missingVerbs,
        matchedResponsibilities,
        missingResponsibilities,
        roleDatasetSize,
        rankPosition,
        benchmarkMethod: 'Percentile',
        semanticEngine: process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'DUMMY_KEY' ? 'Gemini 2.5 Flash' : 'Local 16-D Semantic Fallback',
        recruiterConfidence,
        criticalSkills,
        benchmarkReliability
      },
      reportMarkdown: reportMarkdown.trim(),
      owner: req.user.userId
    });

    // Log event in Chain of Custody
    await logEvent({
      action: 'ats-report-generated',
      entityType: 'Content',
      entityId: report._id,
      performedBy: req.user.userId,
      details: { resumeFile: resume.fileName, jdTitle: jobDescription.title, score: consensusScore }
    });

    return res.status(201).json({
      reportId: report._id,
      scores: report.scores,
      analysis: report.analysis,
      reportMarkdown: report.reportMarkdown
    });

  } catch (error) {
    return next(error);
  }
}

async function getATSReport(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const report = await ATSReport.findById(req.params.id)
      .populate('resumeId', 'fileName metadata')
      .populate('jobDescriptionId', 'title');

    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Access control
    if (String(report.owner) !== String(req.user.userId) && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    return res.status(200).json({ report });
  } catch (error) {
    return next(error);
  }
}

async function getMyATSReports(req, res, next) {
  try {
    const reports = await ATSReport.find({ owner: req.user.userId })
      .populate('resumeId', 'fileName')
      .populate('jobDescriptionId', 'title')
      .sort({ createdAt: -1 });

    return res.status(200).json({ reports });
  } catch (error) {
    return next(error);
  }
}

async function deleteATSReport(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const report = await ATSReport.findById(req.params.id);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    if (String(report.owner) !== String(req.user.userId) && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    await logEvent({
      action: 'ats-report-deleted',
      entityType: 'Content',
      entityId: report._id,
      performedBy: req.user.userId,
      details: { id: report._id }
    });

    await report.deleteOne();
    return res.status(200).json({ message: 'ATS report deleted' });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  analyzeResume,
  getATSReport,
  getMyATSReports,
  deleteATSReport,
  // Helper functions exported for unit testing
  extractLocalEntities,
  parseExperienceYears,
  extractSections,
  evaluateKeywordMatch,
  extractActionVerbs,
  parseContactInfo,
  // V2.1 Helpers
  auditAtsCompatibilityAndRisk,
  detectCareerLevel,
  analyzeCareerProgression
};
