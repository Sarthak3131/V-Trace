import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  FileText, 
  Upload, 
  Trash2, 
  ArrowLeft, 
  AlertTriangle, 
  CheckCircle2, 
  BrainCircuit, 
  FileCheck2, 
  Activity, 
  Terminal, 
  Award, 
  Briefcase, 
  GraduationCap, 
  Settings, 
  AlertCircle,
  Copy,
  Check,
  Plus,
  Link as LinkIcon,
  Mail,
  Phone,
  Sparkles,
  Search
} from 'lucide-react';
import apiClient from '../../lib/axios';
import { useNotificationStore } from '../../store/notificationStore';

interface ATSReportItem {
  _id: string;
  resumeId: {
    _id: string;
    fileName: string;
    metadata?: {
      email?: string;
      phone?: string;
      links?: string[];
      sectionsFound?: string[];
    };
  };
  jobDescriptionId: {
    _id: string;
    title: string;
  };
  scores: {
    consensusScore: number;
    keywordScore: number;
    skillScore: number; // Hiring Manager
    qualityScore: number; // Structural Layout
    recruiterScore: number; // Recruiter Visual
    semanticScore?: number;
    experienceScore?: number;
    atsRiskScore?: number;
    interviewProbability?: number;
    atsCompatibilityScore?: number;
    careerProgressionScore?: number;
    responsibilityCoverage?: number;
    jdCoverageScore?: number;
  };
  analysis: {
    role?: string;
    candidateType?: 'fresher' | 'experienced';
    yearsOfExperience?: number;
    careerLevel?: string;
    resumeSkills: string[];
    jdSkills: string[];
    matchedSkills: string[];
    missingSkills: string[];
    extraSkills?: string[];
    requiredSkills?: string[];
    preferredSkills?: string[];
    learningRoadmap?: {
      priority1?: string[];
      priority2?: string[];
      priority3?: string[];
    };
    benchmarkRank?: string;
    strengths?: string[];
    weaknesses?: string[];
    structureIssues: string[];
    recommendations?: string[];
    recruiterRecommendation?: string;
    semanticReasoning?: string;
    achievementsCount: number;
    actionVerbsUsed: string[];
    matchedKeywords: string[];
    missingKeywords: string[];
    suggestions?: string[];
    compatibilityIssues?: string[];
    compatibilityWarnings?: string[];
    riskFactors?: string[];
    careerProgression?: string;
    recruiterConfidence?: number;
    benchmarkReliability?: string;
    resumeProgress?: {
      previousScore: number;
      currentScore: number;
      improvement: number;
      newSkillsAdded: string[];
      resolvedIssues: string[];
      newIssues: string[];
    };
  };
  reportMarkdown: string;
  createdAt: string;
}

// Inline Markdown Helper
function parseInlineMarkdown(text: string) {
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-cyan-400 font-semibold">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="bg-gray-900 border border-gray-800 text-emerald-300 px-1 py-0.5 rounded text-xs font-mono">{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

// Custom Markdown Renderer
function MarkdownRenderer({ content }: { content: string }) {
  const lines = content.split('\n');
  return (
    <div className="space-y-3.5 text-gray-300 font-sans leading-relaxed text-sm">
      {lines.map((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed) return <div key={idx} className="h-2" />;
        
        if (trimmed.startsWith('# ')) {
          return (
            <h1 key={idx} className="text-xl font-extrabold text-white border-b border-gray-800 pb-2 mb-4 tracking-tight mt-4">
              {parseInlineMarkdown(trimmed.slice(2))}
            </h1>
          );
        }
        
        if (trimmed.startsWith('## ')) {
          return (
            <h2 key={idx} className="text-base font-bold text-gray-100 flex items-center gap-2 mt-5 border-l-2 border-emerald-400 pl-3">
              {parseInlineMarkdown(trimmed.slice(3))}
            </h2>
          );
        }

        if (trimmed.startsWith('### ')) {
          return (
            <h3 key={idx} className="text-sm font-semibold text-gray-200 mt-4 font-mono">
              {parseInlineMarkdown(trimmed.slice(4))}
            </h3>
          );
        }

        if (trimmed.startsWith('* ') || trimmed.startsWith('- ')) {
          return (
            <div key={idx} className="flex gap-2 items-start pl-3">
              <span className="text-emerald-400 mt-1.5 shrink-0 select-none">▪</span>
              <span>{parseInlineMarkdown(trimmed.slice(2))}</span>
            </div>
          );
        }

        if (trimmed === '---') {
          return <hr key={idx} className="border-gray-800 my-4" />;
        }

        return <p key={idx}>{parseInlineMarkdown(trimmed)}</p>;
      })}
    </div>
  );
}

// Circle Gauge Component
function CircularGauge({ score, size = 'large', label }: { score: number; size?: 'small' | 'large'; label: string }) {
  const r = size === 'large' ? 40 : 25;
  const strokeWidth = size === 'large' ? 7 : 4.5;
  const c = 2 * Math.PI * r;
  const offset = c - (c * score) / 100;
  
  const getGradientId = () => `grad-${label.replace(/\s+/g, '-').toLowerCase()}`;

  const getColorClasses = () => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-cyan-400';
    if (score >= 40) return 'text-indigo-400';
    return 'text-red-400';
  };

  return (
    <div className="flex flex-col items-center justify-center p-3 rounded-xl border border-gray-900 bg-gray-950/20 backdrop-blur-sm">
      <div className="relative">
        <svg 
          width={size === 'large' ? 120 : 75} 
          height={size === 'large' ? 120 : 75} 
          viewBox={size === 'large' ? "0 0 100 100" : "0 0 60 60"} 
          className="transform -rotate-90 overflow-visible"
        >
          <defs>
            <linearGradient id={getGradientId()} x1="0%" y1="0%" x2="100%" y2="100%">
              {score >= 80 ? (
                <>
                  <stop offset="0%" stopColor="#10b981" />
                  <stop offset="100%" stopColor="#06b6d4" />
                </>
              ) : score >= 60 ? (
                <>
                  <stop offset="0%" stopColor="#06b6d4" />
                  <stop offset="100%" stopColor="#6366f1" />
                </>
              ) : score >= 40 ? (
                <>
                  <stop offset="0%" stopColor="#6366f1" />
                  <stop offset="100%" stopColor="#a855f7" />
                </>
              ) : (
                <>
                  <stop offset="0%" stopColor="#f43f5e" />
                  <stop offset="100%" stopColor="#fb7185" />
                </>
              )}
            </linearGradient>
          </defs>
          <circle 
            cx={size === 'large' ? 50 : 30} 
            cy={size === 'large' ? 50 : 30} 
            r={r} 
            fill="none" 
            stroke="rgba(255,255,255,0.03)" 
            strokeWidth={strokeWidth} 
          />
          <circle 
            cx={size === 'large' ? 50 : 30} 
            cy={size === 'large' ? 50 : 30} 
            r={r} 
            fill="none" 
            stroke={`url(#${getGradientId()})`} 
            strokeWidth={strokeWidth} 
            strokeDasharray={c} 
            strokeDashoffset={offset} 
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-mono font-bold tracking-tighter ${size === 'large' ? 'text-2xl' : 'text-sm'} ${getColorClasses()}`}>
            {score}%
          </span>
        </div>
      </div>
      <span className={`text-center font-medium mt-2 text-gray-400 ${size === 'large' ? 'text-[11px] uppercase tracking-wider' : 'text-[9px]'}`}>
        {label}
      </span>
    </div>
  );
}

export default function ATSPage() {
  const [view, setView] = useState<'list' | 'create' | 'detail'>('list');
  const [reports, setReports] = useState<ATSReportItem[]>([]);
  const [loadingReports, setLoadingReports] = useState(true);
  const [selectedReport, setSelectedReport] = useState<ATSReportItem | null>(null);

  // Upload fields state
  const [jdTitle, setJdTitle] = useState('');
  const [jdText, setJdText] = useState('');
  const [resumeFile, setResumeFile] = useState<File | null>(null);
  const [jdFile, setJdFile] = useState<File | null>(null);

  // Submit / Processing state
  const [submitting, setSubmitting] = useState(false);
  const [progressStep, setProgressStep] = useState(0);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Detail view active tab
  const [activeTab, setActiveTab] = useState<'summary' | 'skills' | 'recruiter' | 'raw'>('summary');
  const [copied, setCopied] = useState(false);

  const { addNotification } = useNotificationStore();

  const steps = [
    'Initializing secure ingestion channel...',
    'Extracting text stream and resolving MIME structure...',
    'Performing TF-IDF keyword overlap diagnostic checks...',
    'Analyzing hard and soft candidate skill matrices...',
    'Evaluating action verbs and measurable performance metrics...',
    'Auditing resume section parsing layout compatibilities...',
    'Generating consensus score and executing AI perspectives...',
    'Sealing records in V-Trace audit logs database...'
  ];

  // Fetch reports on mount
  useEffect(() => {
    fetchReports();
  }, []);

  // Auto scroll console
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLogs]);

  const fetchReports = async () => {
    try {
      setLoadingReports(true);
      const res = await apiClient.get('/ats/reports');
      setReports(res.data.reports || []);
    } catch (err: any) {
      addNotification(
        'ats-fetch-failed',
        'Fetch Error',
        'Could not load resume reports database.',
        'high'
      );
    } finally {
      setLoadingReports(false);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this report?')) return;
    try {
      await apiClient.delete(`/ats/reports/${id}`);
      setReports(reports.filter(r => r._id !== id));
      if (selectedReport?._id === id) {
        setSelectedReport(null);
        setView('list');
      }
      addNotification(
        'ats-delete-success',
        'Report Removed',
        'ATS compatibility report deleted successfully.',
        'low'
      );
    } catch (err) {
      addNotification(
        'ats-delete-failed',
        'Delete Error',
        'Could not delete the report.',
        'high'
      );
    }
  };

  const handleSelectReport = async (id: string) => {
    try {
      setLoadingReports(true);
      const res = await apiClient.get(`/ats/reports/${id}`);
      setSelectedReport(res.data.report);
      setActiveTab('summary');
      setView('detail');
    } catch (err) {
      addNotification(
        'ats-load-failed',
        'Load Error',
        'Failed to load the selected report.',
        'high'
      );
    } finally {
      setLoadingReports(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, type: 'resume' | 'jd') => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (type === 'resume') {
        setResumeFile(file);
      } else {
        setJdFile(file);
      }
    }
  };

  const runAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resumeFile) {
      alert('Candidate resume file is required.');
      return;
    }
    if (!jdText.trim() && !jdFile) {
      alert('Please provide job requirements by pasting text or uploading a description file.');
      return;
    }

    setSubmitting(true);
    setProgressStep(0);
    setConsoleLogs([`[INFO] Starting Resume Intelligence Engine on ${resumeFile.name}...`]);

    // Step simulation
    const stepInterval = setInterval(() => {
      setProgressStep(prev => {
        const next = prev + 1;
        if (next < steps.length) {
          setConsoleLogs(logs => [
            ...logs,
            `[OK] ${steps[prev]}`,
            `[RUNNING] ${steps[next]}`
          ]);
          return next;
        }
        clearInterval(stepInterval);
        return prev;
      });
    }, 1200);

    try {
      const formData = new FormData();
      formData.append('resumeFile', resumeFile);
      if (jdFile) {
        formData.append('jdFile', jdFile);
      } else {
        formData.append('jdText', jdText);
        formData.append('jdTitle', jdTitle || 'Job Requirement Specification');
      }

      const res = await apiClient.post('/ats/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });

      clearInterval(stepInterval);
      setConsoleLogs(logs => [
        ...logs,
        `[OK] ${steps[steps.length - 1]}`,
        `[SUCCESS] Report sealed. Database Record: ${res.data.reportId}`,
        `[INFO] Analysis complete.`
      ]);

      // Brief delay to appreciate the completion
      await new Promise(r => setTimeout(r, 800));

      addNotification(
        'ats-analyze-success',
        'Analysis Sealed',
        `Evaluated candidate against ${jdTitle || 'Job Requirement'}.`,
        'low'
      );

      // Re-fetch reports list, set detail view
      const detailRes = await apiClient.get(`/ats/reports/${res.data.reportId}`);
      setSelectedReport(detailRes.data.report);
      setReports(prev => [detailRes.data.report, ...prev]);
      
      // Clean up form states
      setResumeFile(null);
      setJdFile(null);
      setJdText('');
      setJdTitle('');

      setActiveTab('summary');
      setView('detail');
    } catch (err: any) {
      clearInterval(stepInterval);
      const errMsg = err.response?.data?.error || 'Analysis failed. Check document structure.';
      setConsoleLogs(logs => [...logs, `[ERROR] ${errMsg}`]);
      addNotification(
        'ats-analyze-failed',
        'Analysis Error',
        errMsg,
        'high'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const copyToClipboard = () => {
    if (!selectedReport) return;
    navigator.clipboard.writeText(selectedReport.reportMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const backCalculateSemantic = (report: ATSReportItem) => {
    const { consensusScore, keywordScore, skillScore, qualityScore, recruiterScore } = report.scores;
    const calc = (consensusScore - (keywordScore * 0.2 + recruiterScore * 0.2 + skillScore * 0.25 + qualityScore * 0.15)) / 0.2;
    return Math.min(Math.max(Math.round(calc), 0), 100);
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans py-8">
      <div className="max-w-6xl mx-auto px-4 space-y-6">
        
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-gray-900 pb-5 gap-4">
          <div className="space-y-1">
            <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
              <BrainCircuit className="h-6 w-6 text-emerald-400" />
              <span>Resume Intelligence Engine</span>
            </h1>
            <p className="text-xs text-gray-400">
              Audit resume structure compatibility and alignment metrics across 10 diagnostic evaluation layers.
            </p>
          </div>
          {view === 'list' && (
            <button
              onClick={() => setView('create')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold px-4 py-2 text-xs transition shadow-md shadow-emerald-500/10"
            >
              <Plus className="h-4 w-4 stroke-[3]" />
              <span>Audit Resume</span>
            </button>
          )}
          {view !== 'list' && (
            <button
              onClick={() => setView('list')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-gray-900 border border-gray-800 text-gray-300 hover:text-white px-4 py-2 text-xs transition"
            >
              <ArrowLeft className="h-4 w-4" />
              <span>Back to Audits</span>
            </button>
          )}
        </div>

        {/* Dynamic Content Views */}
        <AnimatePresence mode="wait">
          
          {/* LIST VIEW */}
          {view === 'list' && (
            <motion.div
              key="list"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              className="space-y-4"
            >
              {loadingReports ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 py-10">
                  {[1, 2, 3].map(i => (
                    <div key={i} className="h-36 rounded-xl border border-gray-900 bg-gray-950/40 animate-pulse" />
                  ))}
                </div>
              ) : reports.length === 0 ? (
                <div className="rounded-2xl border border-gray-900 border-dashed bg-gray-950/20 p-12 text-center max-w-xl mx-auto space-y-4 mt-8">
                  <div className="mx-auto h-12 w-12 rounded-full bg-emerald-500/10 flex items-center justify-center">
                    <FileCheck2 className="h-6 w-6 text-emerald-400" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider">No Resumes Audited Yet</h3>
                    <p className="text-xs text-gray-500">
                      Audit a candidate's resume against a role specification to compute compatibility indices.
                    </p>
                  </div>
                  <button
                    onClick={() => setView('create')}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold px-4 py-2 text-xs transition"
                  >
                    <span>Run First Audit</span>
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {reports.map((report) => (
                    <div
                      key={report._id}
                      onClick={() => handleSelectReport(report._id)}
                      className="group relative cursor-pointer rounded-xl border border-gray-900 bg-gray-950/30 p-5 hover:border-gray-800 hover:bg-gray-950/60 transition shadow-sm flex flex-col justify-between h-44"
                    >
                      <div className="space-y-2">
                        <div className="flex items-start justify-between">
                          <span className="text-[10px] font-mono text-gray-500">
                            {new Date(report.createdAt).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}
                          </span>
                          <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-bold leading-none ${
                            report.scores.consensusScore >= 80 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                            report.scores.consensusScore >= 60 ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
                            'bg-red-500/10 text-red-400 border border-red-500/20'
                          }`}>
                            {report.scores.consensusScore}% Match
                          </span>
                        </div>
                        <div className="space-y-0.5">
                          <h3 className="font-bold text-white text-sm group-hover:text-emerald-400 transition truncate">
                            {report.jobDescriptionId?.title || 'Unknown JD Title'}
                          </h3>
                          <p className="text-xs text-gray-400 flex items-center gap-1 truncate">
                            <FileText className="h-3 w-3 text-gray-500 shrink-0" />
                            <span>{report.resumeId?.fileName}</span>
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center justify-between border-t border-gray-900/60 pt-3 mt-3 text-[10px]">
                        <div className="flex gap-2.5 text-gray-500">
                          <div>Skills: <span className="font-mono text-gray-300 font-semibold">{report.analysis.matchedSkills.length}/{report.analysis.matchedSkills.length + report.analysis.missingSkills.length}</span></div>
                          <div>Issues: <span className="font-mono text-gray-300 font-semibold">{report.analysis.structureIssues.length}</span></div>
                        </div>
                        <button
                          onClick={(e) => handleDelete(report._id, e)}
                          className="text-gray-600 hover:text-red-400 transition p-1 hover:bg-red-500/5 rounded"
                          title="Delete Report"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          )}

          {/* CREATE FORM & LOADING CONSOLE */}
          {view === 'create' && (
            <motion.div
              key="create"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              className="grid grid-cols-1 lg:grid-cols-12 gap-6"
            >
              {submitting ? (
                // Processing loading screen
                <div className="lg:col-span-12 rounded-xl border border-gray-900 bg-gray-950 p-6 flex flex-col items-center justify-center min-h-[400px] space-y-6">
                  <div className="relative flex items-center justify-center">
                    <div className="h-16 w-16 rounded-full border border-gray-900 animate-pulse" />
                    <Activity className="absolute h-8 w-8 text-emerald-400 animate-spin" style={{ animationDuration: '3s' }} />
                  </div>
                  <div className="space-y-1.5 text-center">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider animate-pulse">Running Diagnostic Algorithms</h3>
                    <p className="text-xs text-gray-500 font-mono">Step: {progressStep + 1} / {steps.length} | {steps[progressStep]}</p>
                  </div>
                  
                  {/* Console Log Feed */}
                  <div className="w-full max-w-2xl bg-gray-950 border border-gray-900 rounded-lg p-4 font-mono text-[11px] text-gray-400 space-y-1.5 h-44 overflow-y-auto shadow-inner">
                    <div className="flex items-center gap-1.5 text-emerald-400 border-b border-gray-900 pb-1.5 mb-2 font-bold">
                      <Terminal className="h-3.5 w-3.5" />
                      <span>FORENSIC CONSOLE LOGS</span>
                    </div>
                    {consoleLogs.map((log, i) => (
                      <div key={i} className={
                        log.startsWith('[ERROR]') ? 'text-red-400' :
                        log.startsWith('[SUCCESS]') ? 'text-emerald-400 font-semibold' :
                        log.startsWith('[OK]') ? 'text-gray-300' : 'text-gray-500'
                      }>
                        {log}
                      </div>
                    ))}
                    <div ref={consoleEndRef} />
                  </div>
                </div>
              ) : (
                // Form Interface
                <form onSubmit={runAnalysis} className="lg:col-span-12 grid grid-cols-1 lg:grid-cols-12 gap-6">
                  {/* Left Column: File uploads */}
                  <div className="lg:col-span-5 space-y-5">
                    {/* Resume Upload Box */}
                    <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                        <FileText className="h-4 w-4 text-emerald-400" />
                        <span>Candidate Resume</span>
                      </h3>
                      <p className="text-[10px] text-gray-500">Upload resume file in PDF, DOCX, or plain TXT format.</p>
                      
                      <div className="relative border border-dashed border-gray-800 hover:border-gray-700 rounded-lg bg-gray-950/40 p-6 flex flex-col items-center justify-center cursor-pointer transition">
                        <input
                          type="file"
                          accept=".pdf,.docx,.doc,.txt"
                          onChange={(e) => handleFileChange(e, 'resume')}
                          className="absolute inset-0 opacity-0 cursor-pointer"
                        />
                        <Upload className="h-7 w-7 text-gray-600 mb-2" />
                        <span className="text-[11px] text-gray-300 font-medium">
                          {resumeFile ? resumeFile.name : 'Choose file or drag here'}
                        </span>
                        {resumeFile && (
                          <span className="text-[9px] text-gray-500 mt-1 font-mono">
                            {(resumeFile.size / 1024).toFixed(1)} KB
                          </span>
                        )}
                      </div>
                    </div>

                    {/* JD File Option (Optional) */}
                    <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                        <Upload className="h-4 w-4 text-cyan-400" />
                        <span>Upload JD Document (Optional)</span>
                      </h3>
                      <p className="text-[10px] text-gray-500">Alternatively, upload the JD as a file to extract requirements.</p>
                      
                      <div className="relative border border-dashed border-gray-800 hover:border-gray-700 rounded-lg bg-gray-950/40 p-4 flex flex-col items-center justify-center cursor-pointer transition">
                        <input
                          type="file"
                          accept=".pdf,.docx,.doc,.txt"
                          onChange={(e) => handleFileChange(e, 'jd')}
                          className="absolute inset-0 opacity-0 cursor-pointer"
                        />
                        <span className="text-[11px] text-gray-400 font-medium">
                          {jdFile ? jdFile.name : 'Select Job Spec document'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right Column: Paste Requirements */}
                  <div className="lg:col-span-7 rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4 flex flex-col">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                      <Settings className="h-4 w-4 text-emerald-400" />
                      <span>Role Requirements Specifications</span>
                    </h3>
                    <p className="text-[10px] text-gray-500">Provide requirement copy parameters for matching overlap.</p>
                    
                    <div className="space-y-3 flex-1 flex flex-col">
                      {!jdFile && (
                        <>
                          <div>
                            <label className="block text-[10px] uppercase font-bold text-gray-400 mb-1 font-mono">Job Title / Seniority</label>
                            <input
                              type="text"
                              value={jdTitle}
                              onChange={(e) => setJdTitle(e.target.value)}
                              placeholder="e.g. Senior Frontend Engineer"
                              className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-white placeholder-gray-600 focus:border-emerald-500/50 outline-none transition"
                              required={!jdFile}
                            />
                          </div>

                          <div className="flex-1 flex flex-col">
                            <label className="block text-[10px] uppercase font-bold text-gray-400 mb-1 font-mono">Job Description / Requirements Copy</label>
                            <textarea
                              value={jdText}
                              onChange={(e) => setJdText(e.target.value)}
                              placeholder="Paste the job description copy here. Hard and soft skills, tools, frameworks, and qualifications will be parsed..."
                              className="w-full flex-1 min-h-[160px] rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-white placeholder-gray-600 focus:border-emerald-500/50 outline-none transition resize-none"
                              required={!jdFile}
                            />
                          </div>
                        </>
                      )}

                      {jdFile && (
                        <div className="flex-1 flex flex-col justify-center items-center p-8 bg-gray-950/50 rounded-lg border border-gray-900/60 text-center space-y-2">
                          <CheckCircle2 className="h-8 w-8 text-cyan-400" />
                          <p className="text-xs text-gray-300">Using specifications parsed from uploaded file: <strong className="text-white font-semibold">{jdFile.name}</strong></p>
                          <button
                            type="button"
                            onClick={() => setJdFile(null)}
                            className="text-[10px] text-red-400 underline hover:text-red-300 font-mono"
                          >
                            Reset and Paste Text instead
                          </button>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions Bar */}
                  <div className="lg:col-span-12 flex justify-end border-t border-gray-900/60 pt-4 mt-2">
                    <button
                      type="submit"
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold px-6 py-2.5 text-xs transition shadow-lg shadow-emerald-500/10"
                    >
                      <Sparkles className="h-3.5 w-3.5 fill-gray-950" />
                      <span>Sealed Run Audit</span>
                    </button>
                  </div>
                </form>
              )}
            </motion.div>
          )}

          {/* DETAIL REPORT VIEW */}
          {view === 'detail' && selectedReport && (
            <motion.div
              key="detail"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              className="space-y-6"
            >
              {/* Report Summary Card Header */}
              <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div className="space-y-1">
                  <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest block">COMPATIBILITY REPORT RESOLVED</span>
                  <h2 className="text-lg font-bold text-white leading-tight">
                    {selectedReport.jobDescriptionId?.title || 'Job Requirements'}
                  </h2>
                  <div className="flex items-center gap-3 text-xs text-gray-400 font-mono">
                    <span className="flex items-center gap-1"><FileText className="h-3.5 w-3.5" /> {selectedReport.resumeId?.fileName}</span>
                    <span>•</span>
                    <span>{new Date(selectedReport.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>

                <div className="flex gap-2.5">
                  <button
                    onClick={copyToClipboard}
                    className="inline-flex items-center gap-1 rounded-lg bg-gray-900 border border-gray-800 text-gray-300 hover:text-white px-3 py-2 text-xs transition"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy Report'}</span>
                  </button>
                  <button
                    onClick={(e) => handleDelete(selectedReport._id, e)}
                    className="inline-flex items-center gap-1 rounded-lg bg-red-950/20 border border-red-900/40 text-red-400 hover:bg-red-950/40 px-3 py-2 text-xs transition"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    <span>Delete</span>
                  </button>
                </div>
              </div>

              {/* Multi-Engine Gauges Panel */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Consensus Big Circle */}
                <div className="lg:col-span-3 flex flex-col items-center justify-center p-5 rounded-2xl border border-gray-900 bg-gray-950/30">
                  <div className="mb-3 text-center space-y-0.5">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">Consensus Score</h3>
                    <p className="text-[9px] text-gray-500">Weighted combination of 7 perspectives</p>
                  </div>
                  <CircularGauge score={selectedReport.scores.consensusScore} size="large" label="Consensus Score" />
                </div>

                {/* Recruiter Confidence & JD Coverage Gauges */}
                <div className="lg:col-span-3 flex flex-col justify-around p-5 rounded-2xl border border-gray-900 bg-gray-950/30 gap-4">
                  <div className="flex items-center gap-3">
                    <CircularGauge score={selectedReport.analysis.recruiterConfidence ?? 100} size="small" label="Recruiter Confidence" />
                    <div className="space-y-1">
                      <div className="text-[9px] font-mono text-gray-500">RECRUITER CERTAINTY</div>
                      <p className="text-[11px] text-gray-400">Certainty level of hiring recommendation.</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <CircularGauge score={selectedReport.scores.jdCoverageScore ?? 0} size="small" label="JD Coverage" />
                    <div className="space-y-1">
                      <div className="text-[9px] font-mono text-gray-500">REQUIREMENTS ALIGNMENT</div>
                      <p className="text-[11px] text-gray-400">Technical, operational, and experience alignment.</p>
                    </div>
                  </div>
                </div>

                {/* Perspective Small Circles */}
                <div className="lg:col-span-6 p-5 rounded-2xl border border-gray-900 bg-gray-950/30 space-y-4">
                  <div className="border-b border-gray-900 pb-2">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">Independent Engine Perspectives</h3>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-4 gap-3">
                    <CircularGauge score={selectedReport.scores.keywordScore} size="small" label="Keyword Overlap" />
                    <CircularGauge score={selectedReport.scores.skillScore} size="small" label="Weighted Skill Match" />
                    <CircularGauge score={selectedReport.scores.recruiterScore} size="small" label="Recruiter Visual" />
                    <CircularGauge score={selectedReport.scores.qualityScore} size="small" label="Structural Layout" />
                    <CircularGauge score={selectedReport.scores.semanticScore !== undefined ? selectedReport.scores.semanticScore : backCalculateSemantic(selectedReport)} size="small" label="Semantic Match" />
                    <CircularGauge score={selectedReport.scores.experienceScore || 0} size="small" label="Experience Align" />
                    <CircularGauge score={selectedReport.scores.responsibilityCoverage || 0} size="small" label="Responsibility Coverage" />
                    <CircularGauge score={100 - (selectedReport.scores.atsRiskScore || 0)} size="small" label="ATS Compatibility" />
                  </div>
                </div>
              </div>

              {/* Recruiter Intelligence Stats Bar */}
              <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                <div className="p-3.5 rounded-xl border border-gray-900 bg-gray-950/40 text-center">
                  <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1 font-mono">Detected Role</div>
                  <div className="text-xs text-white font-extrabold truncate" title={selectedReport.analysis.role || 'N/A'}>
                    {selectedReport.analysis.role || 'N/A'}
                  </div>
                </div>
                <div className="p-3.5 rounded-xl border border-gray-900 bg-gray-950/40 text-center">
                  <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1 font-mono">Career Level</div>
                  <div className="text-xs text-emerald-400 font-extrabold">{selectedReport.analysis.careerLevel || 'N/A'}</div>
                </div>
                <div className="p-3.5 rounded-xl border border-gray-900 bg-gray-950/40 text-center">
                  <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1 font-mono">Years of Exp</div>
                  <div className="text-xs text-white font-extrabold">{selectedReport.analysis.yearsOfExperience ?? 0} Year(s)</div>
                </div>
                <div className="p-3.5 rounded-xl border border-gray-900 bg-gray-950/40 text-center">
                  <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1 font-mono">Candidate Type</div>
                  <div className="text-xs text-cyan-400 font-extrabold capitalize">{selectedReport.analysis.candidateType || 'N/A'}</div>
                </div>
                <div className="p-3.5 rounded-xl border border-gray-900 bg-gray-950/40 text-center">
                  <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1 font-mono">Benchmark Rank</div>
                  <div className="text-xs text-indigo-400 font-extrabold">{selectedReport.analysis.benchmarkRank || 'Below Average'}</div>
                </div>
                <div className="p-3.5 rounded-xl border border-gray-900 bg-gray-950/40 text-center flex flex-col justify-center items-center">
                  <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1 font-mono">Recommendation</div>
                  <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-bold leading-none ${
                    selectedReport.analysis.recruiterRecommendation === 'Strong Shortlist' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                    selectedReport.analysis.recruiterRecommendation === 'Shortlist' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
                    selectedReport.analysis.recruiterRecommendation === 'Consider' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' :
                    'bg-red-500/10 text-red-400 border border-red-500/20'
                  }`}>
                    {selectedReport.analysis.recruiterRecommendation || 'Consider'}
                  </span>
                </div>
              </div>

              {/* Tabs Navigation */}
              <div className="flex border-b border-gray-900 text-xs">
                {(['summary', 'skills', 'recruiter', 'raw'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-3 font-bold uppercase tracking-wider border-b-2 transition ${
                      activeTab === tab 
                        ? 'border-emerald-500 text-emerald-400' 
                        : 'border-transparent text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {tab === 'summary' && 'Forensic Summary'}
                    {tab === 'skills' && 'Skills & Keywords'}
                    {tab === 'recruiter' && 'Visual & Structure'}
                    {tab === 'raw' && 'Full Report'}
                  </button>
                ))}
              </div>

              {/* Tab Panels */}
              <div className="min-h-[300px]">
                
                {/* 1. FORENSIC SUMMARY / SUGGESTIONS */}
                {activeTab === 'summary' && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="space-y-6"
                  >
                    {/* 5 NEW ENTERPRISE DASHBOARD PANELS */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                      
                      {/* PANEL 1: ATS COMPATIBILITY ENGINE */}
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4 flex flex-col justify-between">
                        <div>
                          <div className="flex justify-between items-center border-b border-gray-900 pb-2 mb-3">
                            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                              <FileCheck2 className="h-4 w-4 text-emerald-400" />
                              <span>ATS Compatibility Layer</span>
                            </h3>
                            <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-1.5 py-0.5 rounded font-bold">
                              Health Score
                            </span>
                          </div>
                          
                          <div className="flex items-center gap-4 py-2">
                            <CircularGauge score={selectedReport.scores.atsCompatibilityScore ?? 100} size="small" label="Compatibility" />
                            <div className="space-y-1">
                              <div className="text-[10px] font-mono text-gray-500">PARSED FORMAT DIAGNOSTIC</div>
                              <div className="text-xs font-semibold text-gray-300">
                                {(selectedReport.analysis.compatibilityIssues?.length || 0) > 0 ? (
                                  <span className="text-red-400 flex items-center gap-1">
                                    <AlertCircle className="h-3 w-3" />
                                    {(selectedReport.analysis.compatibilityIssues?.length || 0)} layout issues detected
                                  </span>
                                ) : (
                                  <span className="text-emerald-400 flex items-center gap-1">
                                    <CheckCircle2 className="h-3 w-3" />
                                    Clean document layout structures
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>

                          {/* Issues & Warnings lists */}
                          {((selectedReport.analysis.compatibilityIssues?.length || 0) > 0 || (selectedReport.analysis.compatibilityWarnings?.length || 0) > 0) && (
                            <div className="space-y-2 mt-3 text-[11px] max-h-32 overflow-y-auto pr-1">
                              {selectedReport.analysis.compatibilityIssues?.map((issue, idx) => (
                                <div key={idx} className="flex gap-2 items-start text-red-400 bg-red-950/10 border border-red-950/20 p-1.5 rounded">
                                  <AlertCircle className="h-3 w-3 shrink-0 mt-0.5" />
                                  <span>{issue}</span>
                                </div>
                              ))}
                              {selectedReport.analysis.compatibilityWarnings?.map((warning, idx) => (
                                <div key={idx} className="flex gap-2 items-start text-yellow-400 bg-yellow-950/10 border border-yellow-950/20 p-1.5 rounded">
                                  <AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" />
                                  <span>{warning}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* PANEL 2: CAREER INTELLIGENCE & PROGRESSION */}
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4 flex flex-col justify-between">
                        <div>
                          <div className="flex justify-between items-center border-b border-gray-900 pb-2 mb-3">
                            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                              <Briefcase className="h-4 w-4 text-cyan-400" />
                              <span>Career Intelligence</span>
                            </h3>
                            <span className="text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-1.5 py-0.5 rounded font-bold">
                              Level Check
                            </span>
                          </div>

                          <div className="space-y-3">
                            <div className="flex items-center gap-3">
                              <div className="px-2.5 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-center shrink-0">
                                <span className="text-[9px] uppercase tracking-wider text-gray-500 font-bold block mb-0.5">Seniority</span>
                                <span className="text-xs text-cyan-400 font-extrabold">{selectedReport.analysis.careerLevel || 'Junior'}</span>
                              </div>
                              <div className="px-2.5 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-center shrink-0">
                                <span className="text-[9px] uppercase tracking-wider text-gray-500 font-bold block mb-0.5">Growth Score</span>
                                <span className="text-xs text-emerald-400 font-extrabold">{selectedReport.scores.careerProgressionScore ?? 100}%</span>
                              </div>
                              <div className="px-2.5 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-center shrink-0">
                                <span className="text-[9px] uppercase tracking-wider text-gray-500 font-bold block mb-0.5">Exp Class</span>
                                <span className="text-xs text-white font-extrabold capitalize">{selectedReport.analysis.candidateType || 'Fresher'}</span>
                              </div>
                            </div>

                            <div className="p-3 rounded-lg border border-gray-900 bg-gray-950/40 text-[11px] leading-relaxed text-gray-300">
                              <span className="text-[8px] font-mono text-gray-500 uppercase block mb-1">PROMOTION TIMELINE AUDIT</span>
                              <p>{selectedReport.analysis.careerProgression || 'No anomalies detected in role timeline hierarchies.'}</p>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* PANEL 3: RESUME PROGRESS TRACKER */}
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4 flex flex-col justify-between">
                        <div>
                          <div className="flex justify-between items-center border-b border-gray-900 pb-2 mb-3">
                            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                              <Activity className="h-4 w-4 text-indigo-400" />
                              <span>Version Comparison</span>
                            </h3>
                            <span className="text-[10px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 px-1.5 py-0.5 rounded font-bold">
                              Progress Tracker
                            </span>
                          </div>

                          <div className="space-y-3">
                            <div className="grid grid-cols-3 gap-2 text-center">
                              <div className="p-2 rounded-lg bg-gray-900 border border-gray-800">
                                <div className="text-[8px] font-mono text-gray-500 uppercase">PREV</div>
                                <div className="text-xs font-bold text-gray-400">{selectedReport.analysis.resumeProgress?.previousScore ?? 0}%</div>
                              </div>
                              <div className="p-2 rounded-lg bg-gray-900 border border-gray-800">
                                <div className="text-[8px] font-mono text-gray-500 uppercase">CURRENT</div>
                                <div className="text-xs font-bold text-white">{selectedReport.analysis.resumeProgress?.currentScore ?? selectedReport.scores.consensusScore}%</div>
                              </div>
                              <div className="p-2 rounded-lg bg-gray-900 border border-gray-800">
                                <div className="text-[8px] font-mono text-gray-500 uppercase">DELTA</div>
                                <div className={`text-xs font-extrabold ${
                                  (selectedReport.analysis.resumeProgress?.improvement ?? 0) >= 0 ? 'text-emerald-400' : 'text-red-400'
                                }`}>
                                  {(selectedReport.analysis.resumeProgress?.improvement ?? 0) >= 0 ? '+' : ''}
                                  {selectedReport.analysis.resumeProgress?.improvement ?? 0}%
                                </div>
                              </div>
                            </div>

                            {selectedReport.analysis.resumeProgress && selectedReport.analysis.resumeProgress.previousScore > 0 ? (
                              <div className="space-y-2 text-[10px] text-gray-300 max-h-24 overflow-y-auto pr-1">
                                {selectedReport.analysis.resumeProgress.newSkillsAdded && selectedReport.analysis.resumeProgress.newSkillsAdded.length > 0 && (
                                  <div className="flex flex-wrap gap-1.5 items-center">
                                    <span className="text-emerald-400 font-bold font-mono">ADDED SKILLS:</span>
                                    {selectedReport.analysis.resumeProgress.newSkillsAdded.map((s, i) => (
                                      <span key={i} className="bg-emerald-950/30 text-emerald-400 border border-emerald-500/25 px-1.5 py-0.5 rounded font-mono text-[9px]">
                                        {s}
                                      </span>
                                    ))}
                                  </div>
                                )}
                                {selectedReport.analysis.resumeProgress.resolvedIssues && selectedReport.analysis.resumeProgress.resolvedIssues.length > 0 && (
                                  <div className="flex flex-wrap gap-1.5 items-center">
                                    <span className="text-cyan-400 font-bold font-mono">RESOLVED ISSUES:</span>
                                    {selectedReport.analysis.resumeProgress.resolvedIssues.map((issue, i) => (
                                      <span key={i} className="bg-cyan-950/30 text-cyan-400 border border-cyan-500/25 px-1.5 py-0.5 rounded text-[9px]">
                                        {issue}
                                      </span>
                                    ))}
                                  </div>
                                )}
                                {selectedReport.analysis.resumeProgress.newIssues && selectedReport.analysis.resumeProgress.newIssues.length > 0 && (
                                  <div className="flex flex-wrap gap-1.5 items-center">
                                    <span className="text-red-400 font-bold font-mono">NEW ISSUES:</span>
                                    {selectedReport.analysis.resumeProgress.newIssues.map((issue, i) => (
                                      <span key={i} className="bg-red-950/30 text-red-400 border border-red-500/25 px-1.5 py-0.5 rounded text-[9px]">
                                        {issue}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ) : (
                              <p className="text-[10px] text-gray-500 italic text-center py-2">
                                Initial analysis version of this resume.
                              </p>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* PANEL 4: ROLE BENCHMARKING */}
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4 flex flex-col justify-between">
                        <div>
                          <div className="flex justify-between items-center border-b border-gray-900 pb-2 mb-3">
                            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                              <Search className="h-4 w-4 text-purple-400" />
                              <span>Role Peer Benchmarking</span>
                            </h3>
                            <span className={`text-[10px] font-mono border px-1.5 py-0.5 rounded font-bold ${
                              selectedReport.analysis.benchmarkReliability === 'High' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                              selectedReport.analysis.benchmarkReliability === 'Medium' ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' :
                              'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                            }`}>
                              Reliability: {selectedReport.analysis.benchmarkReliability || 'Low'}
                            </span>
                          </div>

                          <div className="space-y-3 text-center">
                            <div className="text-[11px] text-gray-400 font-mono">
                              COMPARING AGAINST OTHERS FOR ROLE:
                              <span className="text-white block font-extrabold text-xs tracking-tight mt-0.5 uppercase">
                                {selectedReport.analysis.role || 'Software Engineer'}
                              </span>
                            </div>
                            
                            <div className="p-4 rounded-xl border border-gray-900 bg-gray-950/40 relative overflow-hidden flex flex-col items-center justify-center">
                              <div className="text-[10px] font-bold text-gray-500 font-mono">STANDING PERCENTILE / RANK</div>
                              <div className="text-xl font-black text-purple-400 my-1 font-mono tracking-tighter">
                                {selectedReport.analysis.benchmarkRank || 'Below Average'}
                              </div>
                              <div className="text-[9px] text-gray-400 leading-snug">
                                Standing in V-Trace peer database for this specific role.
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* PANEL 5: ATS INTEGRITY & RISK MAP */}
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4 flex flex-col justify-between">
                        <div>
                          <div className="flex justify-between items-center border-b border-gray-900 pb-2 mb-3">
                            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                              <AlertTriangle className="h-4 w-4 text-red-400" />
                              <span>ATS Integrity & Risk Map</span>
                            </h3>
                            <span className="text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded font-bold">
                              Parser Risk
                            </span>
                          </div>

                          <div className="flex items-center gap-4 py-2">
                            <CircularGauge score={selectedReport.scores.atsRiskScore ?? 0} size="small" label="Risk Index" />
                            <div className="space-y-1">
                              <div className="text-[10px] font-mono text-gray-500">INTEGRITY COMPLIANCE</div>
                              <div className={`text-xs font-bold ${
                                (selectedReport.scores.atsRiskScore ?? 0) >= 55 ? 'text-red-400' :
                                (selectedReport.scores.atsRiskScore ?? 0) >= 30 ? 'text-yellow-400' : 'text-emerald-400'
                              }`}>
                                {(selectedReport.scores.atsRiskScore ?? 0) >= 55 ? 'HIGH Rejection Risk' :
                                 (selectedReport.scores.atsRiskScore ?? 0) >= 30 ? 'MEDIUM Rejection Risk' : 'LOW Rejection Risk'}
                              </div>
                            </div>
                          </div>

                          {/* Risk Factors list */}
                          {selectedReport.analysis.riskFactors && selectedReport.analysis.riskFactors.length > 0 && (
                            <div className="space-y-1 text-[10px] text-gray-400 max-h-24 overflow-y-auto pr-1">
                              <span className="text-[9px] font-mono text-gray-600 uppercase font-bold">Risk Factors Triggered:</span>
                              {selectedReport.analysis.riskFactors.map((rf, i) => (
                                <div key={i} className="flex items-start gap-1.5 py-0.5">
                                  <span className="text-red-500 mt-0.5">•</span>
                                  <span>{rf}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                      <div className="lg:col-span-8 space-y-6">
                        
                        {/* Recruiter Simulation Reasoning */}
                        <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-3">
                          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                            <BrainCircuit className="h-4 w-4 text-emerald-400" />
                            <span>Senior Recruiter Simulation Perspective</span>
                          </h3>
                          <div className="p-4 rounded-xl border border-gray-900 bg-gray-950/60 text-xs leading-relaxed text-gray-300 relative">
                            <span className="absolute -top-2 left-4 px-1.5 py-0.5 rounded bg-gray-900 border border-gray-800 text-[8px] font-mono text-gray-500">15-YEAR LEAD PERSPECTIVE</span>
                            <p>{selectedReport.analysis.semanticReasoning || 'No summary reasoning available.'}</p>
                          </div>
                        </div>

                      {/* Strengths and Weaknesses Grid */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="rounded-xl border border-emerald-950 bg-emerald-950/5 p-5 space-y-3">
                          <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5 font-mono">
                            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                            <span>Candidate Key Strengths</span>
                          </h4>
                          {(!selectedReport.analysis.strengths || selectedReport.analysis.strengths.length === 0) ? (
                            <p className="text-[11px] text-gray-500 italic">No key strengths parsed.</p>
                          ) : (
                            <ul className="space-y-1.5 text-xs text-gray-300 list-disc list-inside">
                              {selectedReport.analysis.strengths.map((str, idx) => (
                                <li key={idx} className="leading-snug">{str}</li>
                              ))}
                            </ul>
                          )}
                        </div>

                        <div className="rounded-xl border border-red-950 bg-red-950/5 p-5 space-y-3">
                          <h4 className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5 font-mono">
                            <AlertCircle className="h-4 w-4 text-red-400" />
                            <span>Identified Skill Gaps / Weaknesses</span>
                          </h4>
                          {(!selectedReport.analysis.weaknesses || selectedReport.analysis.weaknesses.length === 0) ? (
                            <p className="text-[11px] text-gray-500 italic">No critical deficiencies logged.</p>
                          ) : (
                            <ul className="space-y-1.5 text-xs text-gray-300 list-disc list-inside">
                              {selectedReport.analysis.weaknesses.map((weak, idx) => (
                                <li key={idx} className="leading-snug">{weak}</li>
                              ))}
                            </ul>
                          )}
                        </div>
                      </div>

                      {/* Action items Recommendations */}
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                          <AlertTriangle className="h-4 w-4 text-cyan-400" />
                          <span>Key Recommendations & Action Items</span>
                        </h3>
                        
                        {(() => {
                          const suggestions = selectedReport.analysis.suggestions || selectedReport.analysis.recommendations || [];
                          if (suggestions.length === 0) {
                            return (
                              <div className="p-6 text-center space-y-2 border border-gray-900 bg-gray-950/40 rounded-lg">
                                <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto" />
                                <p className="text-xs text-gray-300 font-semibold">Resume is highly optimized!</p>
                                <p className="text-[10px] text-gray-500">No major formatting or skill deficiencies were flagged by the parser.</p>
                              </div>
                            );
                          }
                          return (
                            <div className="space-y-2.5">
                              {suggestions.map((sug, i) => (
                                <div key={i} className="flex gap-3 items-start p-3 rounded-lg border border-gray-900 bg-gray-950/30">
                                  <span className="h-4 w-4 rounded-full bg-cyan-950 text-cyan-400 flex items-center justify-center text-[10px] font-bold font-mono shrink-0 mt-0.5">
                                    {i + 1}
                                  </span>
                                  <p className="text-xs leading-normal text-gray-300">
                                    {parseInlineMarkdown(sug)}
                                  </p>
                                </div>
                              ))}
                            </div>
                          );
                        })()}
                      </div>
                    </div>

                    {/* Learning Roadmap Widget */}
                    <div className="lg:col-span-4 space-y-4">
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                          <Award className="h-4 w-4 text-emerald-400" />
                          <span>Actionable Learning Roadmap</span>
                        </h3>
                        <p className="text-[10px] text-gray-500 leading-snug">Continuous learning path prioritised by key requirement match weights.</p>

                        <div className="space-y-3.5">
                          {/* Priority 1 */}
                          <div className="space-y-1.5 p-3 rounded-lg border border-red-950 bg-red-950/5">
                            <div className="flex justify-between items-center">
                              <span className="text-[10px] font-mono font-bold text-red-400">PRIORITY 1: REQUIRED GAPS</span>
                              <span className="text-[8px] bg-red-500/10 border border-red-500/20 text-red-400 font-mono px-1 rounded uppercase font-bold">High</span>
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                              {(!selectedReport.analysis.learningRoadmap?.priority1 || selectedReport.analysis.learningRoadmap.priority1.length === 0) ? (
                                <span className="text-[10px] text-gray-500 italic">No missing required skills.</span>
                              ) : (
                                selectedReport.analysis.learningRoadmap.priority1.map((s, idx) => (
                                  <span key={idx} className="rounded bg-red-950/40 border border-red-500/20 px-2 py-0.5 text-[9px] font-bold font-mono text-red-300 uppercase">
                                    {s}
                                  </span>
                                ))
                              )}
                            </div>
                          </div>

                          {/* Priority 2 */}
                          <div className="space-y-1.5 p-3 rounded-lg border border-indigo-950 bg-indigo-950/5">
                            <div className="flex justify-between items-center">
                              <span className="text-[10px] font-mono font-bold text-indigo-400">PRIORITY 2: PREFERRED GAPS</span>
                              <span className="text-[8px] bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 font-mono px-1 rounded uppercase font-bold">Medium</span>
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                              {(!selectedReport.analysis.learningRoadmap?.priority2 || selectedReport.analysis.learningRoadmap.priority2.length === 0) ? (
                                <span className="text-[10px] text-gray-500 italic">No missing preferred skills.</span>
                              ) : (
                                selectedReport.analysis.learningRoadmap.priority2.map((s, idx) => (
                                  <span key={idx} className="rounded bg-indigo-950/40 border border-indigo-500/20 px-2 py-0.5 text-[9px] font-bold font-mono text-indigo-300 uppercase">
                                    {s}
                                  </span>
                                ))
                              )}
                            </div>
                          </div>

                          {/* Priority 3 */}
                          <div className="space-y-1.5 p-3 rounded-lg border border-cyan-950 bg-cyan-950/5">
                            <div className="flex justify-between items-center">
                              <span className="text-[10px] font-mono font-bold text-cyan-400">PRIORITY 3: RELATED SKILLS</span>
                              <span className="text-[8px] bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono px-1 rounded uppercase font-bold">Optional</span>
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                              {(!selectedReport.analysis.learningRoadmap?.priority3 || selectedReport.analysis.learningRoadmap.priority3.length === 0) ? (
                                <span className="text-[10px] text-gray-500 italic">No recommended related skills.</span>
                              ) : (
                                selectedReport.analysis.learningRoadmap.priority3.map((s, idx) => (
                                  <span key={idx} className="rounded bg-cyan-950/40 border border-cyan-500/20 px-2 py-0.5 text-[9px] font-bold font-mono text-cyan-300 uppercase">
                                    {s}
                                  </span>
                                ))
                              )}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Audit Metadata Box */}
                      <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-3.5">
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">Audit Metadata</h3>
                        
                        <div className="space-y-2 font-mono text-[10px] text-gray-400">
                          <div className="flex justify-between py-1 border-b border-gray-900/60">
                            <span>Resume Format</span>
                            <span className="text-white uppercase font-bold">{selectedReport.resumeId?.fileName.split('.').pop() || 'Unknown'}</span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-gray-900/60">
                            <span>Achievements Found</span>
                            <span className="text-white font-bold">{selectedReport.analysis.achievementsCount}</span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-gray-900/60">
                            <span>Action Verbs Count</span>
                            <span className="text-white font-bold">{selectedReport.analysis.actionVerbsUsed.length}</span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-gray-900/60">
                            <span>ATS Compatibility Score</span>
                            <span className="text-white font-bold">{100 - (selectedReport.scores.atsRiskScore || 0)}%</span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-gray-900/60">
                            <span>ATS Rejection Risk</span>
                            <span className={`font-bold ${
                              (selectedReport.scores.atsRiskScore || 0) >= 50 ? 'text-red-400' :
                              (selectedReport.scores.atsRiskScore || 0) >= 25 ? 'text-yellow-400' : 'text-emerald-400'
                            }`}>
                              {(selectedReport.scores.atsRiskScore || 0)}%
                            </span>
                          </div>
                          <div className="flex justify-between py-1">
                            <span>Audit Chain Hash</span>
                            <span className="text-cyan-400 truncate w-32 text-right font-mono" title={selectedReport._id}>
                              {selectedReport._id}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                    </div>
                  </motion.div>
                )}

                {/* 2. SKILLS & KEYWORDS */}
                {activeTab === 'skills' && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="grid grid-cols-1 md:grid-cols-2 gap-6"
                  >
                    {/* Skills Overlaps */}
                    <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                        <Award className="h-4 w-4 text-emerald-400" />
                        <span>JD Target Skills Breakdown</span>
                      </h3>
                      
                      <div className="space-y-4">
                        {/* 1. Critical Skills */}
                        <div className="space-y-2 p-3 rounded-lg border border-red-950 bg-red-950/5">
                          <div className="flex justify-between items-center border-b border-red-950/30 pb-1.5 mb-2">
                            <span className="text-[10px] font-mono font-bold text-red-400">CRITICAL SKILLS (WEIGHT 3)</span>
                            <span className="text-[10px] font-mono font-bold text-red-400">
                              {(() => {
                                const crit = selectedReport.analysis.criticalSkills || [];
                                const matched = crit.filter(s => selectedReport.analysis.matchedSkills.includes(s));
                                return crit.length > 0 ? Math.round((matched.length / crit.length) * 100) : 100;
                              })()}% Match
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {(!selectedReport.analysis.criticalSkills || selectedReport.analysis.criticalSkills.length === 0) ? (
                              <span className="text-[10px] text-gray-500 italic">None specified.</span>
                            ) : (
                              selectedReport.analysis.criticalSkills.map((s, idx) => {
                                const isMatched = selectedReport.analysis.matchedSkills.includes(s);
                                return (
                                  <span key={idx} className={`rounded-md px-2 py-0.5 text-[9px] font-bold font-mono uppercase ${
                                    isMatched 
                                      ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400' 
                                      : 'border border-red-500/20 bg-red-500/10 text-red-400 line-through'
                                  }`}>
                                    {s}
                                  </span>
                                );
                              })
                            )}
                          </div>
                        </div>

                        {/* 2. Required Skills */}
                        <div className="space-y-2 p-3 rounded-lg border border-indigo-950 bg-indigo-950/5">
                          <div className="flex justify-between items-center border-b border-indigo-950/30 pb-1.5 mb-2">
                            <span className="text-[10px] font-mono font-bold text-indigo-400">REQUIRED SKILLS (WEIGHT 2)</span>
                            <span className="text-[10px] font-mono font-bold text-indigo-400">
                              {(() => {
                                const req = selectedReport.analysis.requiredSkills || [];
                                const matched = req.filter(s => selectedReport.analysis.matchedSkills.includes(s));
                                return req.length > 0 ? Math.round((matched.length / req.length) * 100) : 100;
                              })()}% Match
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {(!selectedReport.analysis.requiredSkills || selectedReport.analysis.requiredSkills.length === 0) ? (
                              <span className="text-[10px] text-gray-500 italic">None specified.</span>
                            ) : (
                              selectedReport.analysis.requiredSkills.map((s, idx) => {
                                const isMatched = selectedReport.analysis.matchedSkills.includes(s);
                                return (
                                  <span key={idx} className={`rounded-md px-2 py-0.5 text-[9px] font-bold font-mono uppercase ${
                                    isMatched 
                                      ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400' 
                                      : 'border border-red-500/20 bg-red-500/10 text-red-400 line-through'
                                  }`}>
                                    {s}
                                  </span>
                                );
                              })
                            )}
                          </div>
                        </div>

                        {/* 3. Preferred Skills */}
                        <div className="space-y-2 p-3 rounded-lg border border-cyan-950 bg-cyan-950/5">
                          <div className="flex justify-between items-center border-b border-cyan-950/30 pb-1.5 mb-2">
                            <span className="text-[10px] font-mono font-bold text-cyan-400">PREFERRED SKILLS (WEIGHT 1)</span>
                            <span className="text-[10px] font-mono font-bold text-cyan-400">
                              {(() => {
                                const pref = selectedReport.analysis.preferredSkills || [];
                                const matched = pref.filter(s => selectedReport.analysis.matchedSkills.includes(s));
                                return pref.length > 0 ? Math.round((matched.length / pref.length) * 100) : 100;
                              })()}% Match
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {(!selectedReport.analysis.preferredSkills || selectedReport.analysis.preferredSkills.length === 0) ? (
                              <span className="text-[10px] text-gray-500 italic">None specified.</span>
                            ) : (
                              selectedReport.analysis.preferredSkills.map((s, idx) => {
                                const isMatched = selectedReport.analysis.matchedSkills.includes(s);
                                return (
                                  <span key={idx} className={`rounded-md px-2 py-0.5 text-[9px] font-bold font-mono uppercase ${
                                    isMatched 
                                      ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-400' 
                                      : 'border border-red-500/20 bg-red-500/10 text-red-400 line-through'
                                  }`}>
                                    {s}
                                  </span>
                                );
                              })
                            )}
                          </div>
                        </div>

                        <div className="space-y-1.5 pt-3 border-t border-gray-900/40">
                          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Extra Resume Skills ({selectedReport.analysis.extraSkills?.length || 0})</span>
                          <div className="flex flex-wrap gap-1.5">
                            {!selectedReport.analysis.extraSkills || selectedReport.analysis.extraSkills.length === 0 ? (
                              <span className="text-[10px] text-gray-600 font-mono">None identified.</span>
                            ) : (
                              selectedReport.analysis.extraSkills.map((s, idx) => (
                                <span key={idx} className="rounded-md border border-cyan-500/20 bg-cyan-500/5 px-2 py-1 text-[10px] font-bold font-mono text-cyan-400 capitalize">
                                  {s}
                                </span>
                              ))
                            )}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Keywords Overlaps */}
                    <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                        <Search className="h-4 w-4 text-cyan-400" />
                        <span>Vocabulary Keyword Overlaps</span>
                      </h3>

                      <div className="space-y-4">
                        <div className="space-y-1.5">
                          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Matched Keywords ({selectedReport.analysis.matchedKeywords?.length || 0})</span>
                          <div className="flex flex-wrap gap-1.5">
                            {!selectedReport.analysis.matchedKeywords || selectedReport.analysis.matchedKeywords.length === 0 ? (
                              <span className="text-[10px] text-gray-600 font-mono">None identified.</span>
                            ) : (
                              selectedReport.analysis.matchedKeywords.map((k, idx) => (
                                <span key={idx} className="rounded bg-gray-900 border border-gray-800 px-1.5 py-0.5 text-[10px] font-mono text-gray-300">
                                  {k}
                                </span>
                              ))
                            )}
                          </div>
                        </div>

                        <div className="space-y-1.5 pt-3 border-t border-gray-900/40">
                          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Missing Keywords ({selectedReport.analysis.missingKeywords?.length || 0})</span>
                          <div className="flex flex-wrap gap-1.5">
                            {!selectedReport.analysis.missingKeywords || selectedReport.analysis.missingKeywords.length === 0 ? (
                              <span className="text-[10px] text-gray-600 font-mono">None identified.</span>
                            ) : (
                              selectedReport.analysis.missingKeywords.slice(0, 20).map((k, idx) => (
                                <span key={idx} className="rounded bg-gray-900 border border-gray-900/40 px-1.5 py-0.5 text-[10px] font-mono text-gray-500 line-through">
                                  {k}
                                </span>
                              ))
                            )}
                            {selectedReport.analysis.missingKeywords && selectedReport.analysis.missingKeywords.length > 20 && (
                              <span className="text-[10px] text-gray-600 font-mono self-center">+{selectedReport.analysis.missingKeywords.length - 20} more</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}

                {/* 3. RECRUITER VISUAL & STRUCTURE AUDIT */}
                {activeTab === 'recruiter' && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="grid grid-cols-1 md:grid-cols-2 gap-6"
                  >
                    {/* Contact & Action Verb checks */}
                    <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                        <Briefcase className="h-4 w-4 text-emerald-400" />
                        <span>Recruiter Impact Diagnostics</span>
                      </h3>

                      <div className="space-y-4">
                        {/* Contact Info Checks */}
                        <div className="space-y-2">
                          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Parsed Contact Information</span>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                            <div className="flex items-center gap-2 rounded-lg border border-gray-900 bg-gray-950/40 p-2.5">
                              <Mail className="h-4 w-4 text-emerald-400 shrink-0" />
                              <span className="truncate text-gray-300 font-mono text-[11px]" title={selectedReport.resumeId?.metadata?.email || 'Missing email'}>
                                {selectedReport.resumeId?.metadata?.email || <span className="text-red-400 italic">No email detected</span>}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 rounded-lg border border-gray-900 bg-gray-950/40 p-2.5">
                              <Phone className="h-4 w-4 text-emerald-400 shrink-0" />
                              <span className="truncate text-gray-300 font-mono text-[11px]" title={selectedReport.resumeId?.metadata?.phone || 'Missing phone'}>
                                {selectedReport.resumeId?.metadata?.phone || <span className="text-red-400 italic">No phone detected</span>}
                              </span>
                            </div>
                          </div>
                          {selectedReport.resumeId?.metadata?.links && selectedReport.resumeId.metadata.links.length > 0 && (
                            <div className="space-y-1 mt-2">
                              <span className="text-[9px] font-mono text-gray-600 uppercase">Parsed Reference Links</span>
                              <div className="space-y-1 max-h-24 overflow-y-auto pr-1">
                                {selectedReport.resumeId.metadata.links.map((link, idx) => (
                                  <a
                                    key={idx}
                                    href={link}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-1.5 text-xs text-cyan-400 hover:underline truncate"
                                  >
                                    <LinkIcon className="h-3 w-3 shrink-0" />
                                    <span>{link}</span>
                                  </a>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Action Verbs */}
                        <div className="space-y-2 pt-3 border-t border-gray-900/60">
                          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Action Verbs Utilized ({selectedReport.analysis.actionVerbsUsed.length})</span>
                          <div className="flex flex-wrap gap-1.5">
                            {selectedReport.analysis.actionVerbsUsed.length === 0 ? (
                              <span className="text-[10px] text-gray-600 font-mono">No strong verbs found. Use dynamic past-tense keywords (e.g. Led, Designed).</span>
                            ) : (
                              selectedReport.analysis.actionVerbsUsed.map((verb, idx) => (
                                <span key={idx} className="rounded border border-gray-900 bg-gray-950 px-2 py-0.5 text-[10px] font-bold text-cyan-400 font-mono capitalize">
                                  {verb}
                                </span>
                              ))
                            )}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Heading Audit & Structure Issues */}
                    <div className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-4">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 font-mono">
                        <GraduationCap className="h-4 w-4 text-cyan-400" />
                        <span>Parsing Heading Structure Layout</span>
                      </h3>

                      <div className="space-y-4">
                        <div className="space-y-2">
                          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Registered Core Sections</span>
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            {['experience', 'education', 'skills', 'projects'].map(sec => {
                              const isFound = selectedReport.resumeId?.metadata?.sectionsFound?.includes(sec);
                              return (
                                <div key={sec} className={`flex items-center gap-2 rounded-lg border p-2.5 ${
                                  isFound ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400' : 'border-red-500/20 bg-red-500/5 text-red-400'
                                }`}>
                                  {isFound ? (
                                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                                  ) : (
                                    <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
                                  )}
                                  <span className="uppercase font-bold tracking-wider text-[10px] font-mono">{sec}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        {selectedReport.analysis.structureIssues && selectedReport.analysis.structureIssues.length > 0 && (
                          <div className="space-y-2 pt-3 border-t border-gray-900/60">
                            <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Structural Deficiencies Flagged</span>
                            <div className="space-y-1.5 text-xs text-red-400">
                              {selectedReport.analysis.structureIssues.map((issue, idx) => (
                                <div key={idx} className="flex gap-2 items-start">
                                  <span className="mt-1.5 shrink-0 text-[10px]">▪</span>
                                  <span>{issue}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </motion.div>
                )}

                {/* 4. RAW REPORT MARKDOWN */}
                {activeTab === 'raw' && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="rounded-xl border border-gray-900 bg-gray-950/40 p-6 shadow-inner font-sans max-w-3xl mx-auto"
                  >
                    <MarkdownRenderer content={selectedReport.reportMarkdown} />
                  </motion.div>
                )}

              </div>
            </motion.div>
          )}

        </AnimatePresence>

      </div>
    </div>
  );
}
