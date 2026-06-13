import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  FileText, 
  Upload, 
  Trash2, 
  ArrowLeft, 
  CheckCircle2, 
  Activity, 
  Terminal, 
  Plus, 
  Sparkles, 
  Copy, 
  Check,
  ShieldAlert,
  Layers
} from 'lucide-react';
import apiClient from '../../lib/axios';
import { useNotificationStore } from '../../store/notificationStore';

interface PlagiarismReportItem {
  _id: string;
  documentId: {
    _id: string;
    title: string;
    fileName: string;
    rawText: string;
  };
  scores: {
    plagiarismIndex: number;
    exactMatchScore: number;
    sequenceScore: number;
    paraphraseScore: number;
    semanticScore: number;
    aiRewriteScore: number;
  };
  matches: Array<{
    matchedDocumentId: string;
    matchedTitle: string;
    similarityScore: number;
    matchingTextSegments: Array<{
      originalSegment: string;
      sourceSegment: string;
      matchType: 'exact' | 'near-match' | 'paraphrased' | 'semantic' | 'ai-rewrite';
    }>;
  }>;
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
  
  const getGradientId = () => `plag-grad-${label.replace(/\s+/g, '-').toLowerCase()}`;

  const getColorClasses = () => {
    if (score >= 50) return 'text-red-400';
    if (score >= 25) return 'text-amber-400';
    return 'text-emerald-400';
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
              {score >= 50 ? (
                <>
                  <stop offset="0%" stopColor="#f43f5e" />
                  <stop offset="100%" stopColor="#fb7185" />
                </>
              ) : score >= 25 ? (
                <>
                  <stop offset="0%" stopColor="#f59e0b" />
                  <stop offset="100%" stopColor="#fbbf24" />
                </>
              ) : (
                <>
                  <stop offset="0%" stopColor="#10b981" />
                  <stop offset="100%" stopColor="#06b6d4" />
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

export default function PlagiarismPage() {
  const [view, setView] = useState<'list' | 'create' | 'detail'>('list');
  const [reports, setReports] = useState<PlagiarismReportItem[]>([]);
  const [loadingReports, setLoadingReports] = useState(true);
  const [selectedReport, setSelectedReport] = useState<PlagiarismReportItem | null>(null);

  // Upload fields state
  const [title, setTitle] = useState('');
  const [docFile, setDocFile] = useState<File | null>(null);

  // Submit / Processing state
  const [submitting, setSubmitting] = useState(false);
  const [progressStep, setProgressStep] = useState(0);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Detail view active tab
  const [activeTab, setActiveTab] = useState<'sources' | 'highlight' | 'raw'>('sources');
  const [copied, setCopied] = useState(false);

  const { addNotification } = useNotificationStore();

  const steps = [
    'Initializing plagiarism check pathway...',
    'Extracting document character string buffers...',
    'Performing verbatim database block-hash queries...',
    'Running sentence-level Levenshtein distance matches...',
    'Auditing token Jaccard overlaps for synonym flips...',
    'Executing Cosine tf-idf semantic correlation vectors...',
    'Calculating stylometric perplexity and transition buzzwords...',
    'Compiling multi-engine consensus plagiarism index report...'
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
      const res = await apiClient.get('/plagiarism/reports');
      setReports(res.data.reports || []);
    } catch (err: any) {
      addNotification(
        'plag-fetch-failed',
        'Fetch Error',
        'Could not load plagiarism reports database.',
        'high'
      );
    } finally {
      setLoadingReports(false);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this report? This will remove the document comparison index as well.')) return;
    try {
      await apiClient.delete(`/plagiarism/reports/${id}`);
      setReports(reports.filter(r => r._id !== id));
      if (selectedReport?._id === id) {
        setSelectedReport(null);
        setView('list');
      }
      addNotification(
        'plag-delete-success',
        'Report Removed',
        'Plagiarism report deleted successfully.',
        'low'
      );
    } catch (err) {
      addNotification(
        'plag-delete-failed',
        'Delete Error',
        'Could not delete the report.',
        'high'
      );
    }
  };

  const handleSelectReport = async (id: string) => {
    try {
      setLoadingReports(true);
      const res = await apiClient.get(`/plagiarism/reports/${id}`);
      setSelectedReport(res.data.report);
      setActiveTab('sources');
      setView('detail');
    } catch (err) {
      addNotification(
        'plag-load-failed',
        'Load Error',
        'Failed to load the selected report.',
        'high'
      );
    } finally {
      setLoadingReports(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setDocFile(file);
      if (!title) {
        // Auto-set title based on file name
        setTitle(file.name.replace(/\.[^/.]+$/, ""));
      }
    }
  };

  const runAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!docFile) {
      alert('Verification document file is required.');
      return;
    }

    setSubmitting(true);
    setProgressStep(0);
    setConsoleLogs([`[INFO] Starting Plagiarism Scan on ${docFile.name}...`]);

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
    }, 1100);

    try {
      const formData = new FormData();
      formData.append('docFile', docFile);
      formData.append('title', title || 'Untitled Forensic Scan');

      const res = await apiClient.post('/plagiarism/check', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });

      clearInterval(stepInterval);
      setConsoleLogs(logs => [
        ...logs,
        `[OK] ${steps[steps.length - 1]}`,
        `[SUCCESS] Plagiarism report generated: ${res.data.reportId}`,
        `[INFO] Ingestion completed.`
      ]);

      await new Promise(r => setTimeout(r, 800));

      addNotification(
        'plag-check-success',
        'Audit Completed',
        `Plagiarism index: ${res.data.scores.plagiarismIndex}%`,
        res.data.scores.plagiarismIndex > 30 ? 'high' : 'low'
      );

      // Re-fetch reports list, set detail view
      const detailRes = await apiClient.get(`/plagiarism/reports/${res.data.reportId}`);
      setSelectedReport(detailRes.data.report);
      setReports(prev => [detailRes.data.report, ...prev]);
      
      setDocFile(null);
      setTitle('');

      setActiveTab('sources');
      setView('detail');
    } catch (err: any) {
      clearInterval(stepInterval);
      const errMsg = err.response?.data?.error || 'Plagiarism audit failed.';
      setConsoleLogs(logs => [...logs, `[ERROR] ${errMsg}`]);
      addNotification(
        'plag-check-failed',
        'Audit Error',
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

  // Turnitin-style highlighter
  const renderHighlightedDocument = () => {
    if (!selectedReport) return null;
    const { rawText } = selectedReport.documentId;
    if (!rawText) return <p className="text-xs text-gray-500 italic">No document text parsed.</p>;

    // Collect all matched segments
    const segments: Array<{ segment: string; matchType: string; sourceTitle: string }> = [];
    selectedReport.matches.forEach(m => {
      m.matchingTextSegments.forEach(seg => {
        segments.push({
          segment: seg.originalSegment,
          matchType: seg.matchType,
          sourceTitle: m.matchedTitle
        });
      });
    });

    if (segments.length === 0) {
      return (
        <div className="space-y-4 text-sm leading-relaxed text-gray-300 font-sans">
          {rawText.split('\n').map((para, i) => (
            <p key={i}>{para}</p>
          ))}
        </div>
      );
    }

    // Split text into paragraphs, then check sentences
    const paragraphs = rawText.split(/\n+/);
    return (
      <div className="space-y-4 text-sm leading-relaxed text-gray-300 font-sans max-h-[500px] overflow-y-auto pr-2">
        {paragraphs.map((para, pIdx) => {
          if (!para.trim()) return null;
          
          // Split paragraph into sentences/delimiters
          const pieces = para.split(/([.!?]+)/g);
          
          return (
            <p key={pIdx}>
              {pieces.map((piece, pieceIdx) => {
                if (!piece.trim() || /^[.!?]+$/.test(piece)) {
                  // return delimiters directly
                  return piece;
                }
                
                // Find matching segment
                const match = segments.find(seg => {
                  const cleanedPiece = piece.toLowerCase().replace(/[^\w]/g, ' ').replace(/\s+/g, ' ').trim();
                  const cleanedSeg = seg.segment.toLowerCase().replace(/[^\w]/g, ' ').replace(/\s+/g, ' ').trim();
                  return cleanedPiece.includes(cleanedSeg) || cleanedSeg.includes(cleanedPiece);
                });

                if (match) {
                  // Highlight colors
                  const getHighlightStyle = () => {
                    if (match.matchType === 'exact') return 'bg-red-500/20 text-red-200 border-b border-red-500 hover:bg-red-500/30';
                    if (match.matchType === 'near-match') return 'bg-amber-500/20 text-amber-200 border-b border-amber-500 hover:bg-amber-500/30';
                    if (match.matchType === 'paraphrased') return 'bg-indigo-500/20 text-indigo-200 border-b border-indigo-500 hover:bg-indigo-500/30';
                    return 'bg-purple-500/20 text-purple-200 border-b border-purple-500 hover:bg-purple-500/30';
                  };

                  return (
                    <span 
                      key={pieceIdx} 
                      className={`relative cursor-help px-1 py-0.5 rounded transition ${getHighlightStyle()}`}
                      title={`Match: ${match.matchType.toUpperCase()} | Source: ${match.sourceTitle}`}
                    >
                      {piece}
                    </span>
                  );
                }

                return piece;
              })}
            </p>
          );
        })}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans py-8">
      <div className="max-w-6xl mx-auto px-4 space-y-6">
        
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-gray-900 pb-5 gap-4">
          <div className="space-y-1">
            <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
              <Layers className="h-6 w-6 text-emerald-400" />
              <span>Plagiarism Detection System</span>
            </h1>
            <p className="text-xs text-gray-400">
              Check documents for verbatim copying, near-match modifications, synonym swaps, and semantic overlap indicators.
            </p>
          </div>
          {view === 'list' && (
            <button
              onClick={() => setView('create')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold px-4 py-2 text-xs transition shadow-md shadow-emerald-500/10"
            >
              <Plus className="h-4 w-4 stroke-[3]" />
              <span>Check Document</span>
            </button>
          )}
          {view !== 'list' && (
            <button
              onClick={() => setView('list')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-gray-900 border border-gray-800 text-gray-300 hover:text-white px-4 py-2 text-xs transition"
            >
              <ArrowLeft className="h-4 w-4" />
              <span>Back to Reports</span>
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
                    <ShieldAlert className="h-6 w-6 text-emerald-400" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider">No Plagiarism Reports Resolved</h3>
                    <p className="text-xs text-gray-500">
                      Audit a document against V-Trace database records to verify text authenticity and copyright overlaps.
                    </p>
                  </div>
                  <button
                    onClick={() => setView('create')}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold px-4 py-2 text-xs transition"
                  >
                    <span>Run Verification Scan</span>
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
                            report.scores.plagiarismIndex >= 40 ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                            report.scores.plagiarismIndex >= 15 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                            'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          }`}>
                            {report.scores.plagiarismIndex}% Plagiarized
                          </span>
                        </div>
                        <div className="space-y-0.5">
                          <h3 className="font-bold text-white text-sm group-hover:text-emerald-400 transition truncate">
                            {report.documentId?.title || 'Ingested Document'}
                          </h3>
                          <p className="text-xs text-gray-400 flex items-center gap-1 truncate">
                            <FileText className="h-3 w-3 text-gray-500 shrink-0" />
                            <span>{report.documentId?.fileName}</span>
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center justify-between border-t border-gray-900/60 pt-3 mt-3 text-[10px]">
                        <div className="flex gap-2.5 text-gray-500">
                          <div>Matches: <span className="font-mono text-gray-300 font-semibold">{report.matches.length} sources</span></div>
                          <div>AI score: <span className="font-mono text-gray-300 font-semibold">{report.scores.aiRewriteScore}%</span></div>
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
              className="max-w-2xl mx-auto"
            >
              {submitting ? (
                // Processing loading screen
                <div className="rounded-xl border border-gray-900 bg-gray-950 p-6 flex flex-col items-center justify-center min-h-[400px] space-y-6">
                  <div className="relative flex items-center justify-center">
                    <div className="h-16 w-16 rounded-full border border-gray-900 animate-pulse" />
                    <Activity className="absolute h-8 w-8 text-emerald-400 animate-spin" style={{ animationDuration: '3s' }} />
                  </div>
                  <div className="space-y-1.5 text-center">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider animate-pulse">Running Plagiarism Algorithms</h3>
                    <p className="text-xs text-gray-500 font-mono">Step: {progressStep + 1} / {steps.length} | {steps[progressStep]}</p>
                  </div>
                  
                  {/* Console Log Feed */}
                  <div className="w-full bg-gray-950 border border-gray-900 rounded-lg p-4 font-mono text-[11px] text-gray-400 space-y-1.5 h-44 overflow-y-auto shadow-inner">
                    <div className="flex items-center gap-1.5 text-emerald-400 border-b border-gray-900 pb-1.5 mb-2 font-bold">
                      <Terminal className="h-3.5 w-3.5" />
                      <span>PLAGIARISM CHECK CONSOLE LOGS</span>
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
                <form onSubmit={runAnalysis} className="rounded-xl border border-gray-900 bg-gray-950/20 p-6 space-y-5">
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                      <Layers className="h-4.5 w-4.5 text-emerald-400" />
                      <span>Verify File Authenticity</span>
                    </h3>
                    <p className="text-xs text-gray-500">Provide document copy to index and run verification scans.</p>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <label className="block text-[10px] uppercase font-bold text-gray-400 mb-1 font-mono">Document Title</label>
                      <input
                        type="text"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        placeholder="e.g. Research Thesis Draft V1"
                        className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-white placeholder-gray-600 focus:border-emerald-500/50 outline-none transition"
                        required
                      />
                    </div>

                    {/* Document Upload Box */}
                    <div className="space-y-1">
                      <label className="block text-[10px] uppercase font-bold text-gray-400 mb-1.5 font-mono">Document File</label>
                      <div className="relative border border-dashed border-gray-800 hover:border-gray-700 rounded-lg bg-gray-950/40 p-8 flex flex-col items-center justify-center cursor-pointer transition">
                        <input
                          type="file"
                          accept=".pdf,.docx,.doc,.txt"
                          onChange={handleFileChange}
                          className="absolute inset-0 opacity-0 cursor-pointer"
                        />
                        <Upload className="h-8 w-8 text-gray-600 mb-2" />
                        <span className="text-xs text-gray-300 font-medium">
                          {docFile ? docFile.name : 'Choose document file or drag here'}
                        </span>
                        <span className="text-[10px] text-gray-500 mt-1">Supports PDF, DOCX, TXT (Max 10MB)</span>
                        {docFile && (
                          <span className="text-[9px] font-mono text-emerald-400 mt-1 font-bold">
                            {(docFile.size / 1024).toFixed(1)} KB selected
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Actions Bar */}
                  <div className="flex justify-end border-t border-gray-900/60 pt-4 mt-3">
                    <button
                      type="submit"
                      disabled={!docFile}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-gray-950 disabled:opacity-40 disabled:cursor-not-allowed font-bold px-5 py-2 text-xs transition"
                    >
                      <Sparkles className="h-3.5 w-3.5 fill-gray-950" />
                      <span>Run Verification Scan</span>
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
                  <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest block">PLAGIARISM VERDICT RESOLVED</span>
                  <h2 className="text-lg font-bold text-white leading-tight">
                    {selectedReport.documentId?.title || 'Audit Document'}
                  </h2>
                  <div className="flex items-center gap-3 text-xs text-gray-400 font-mono">
                    <span className="flex items-center gap-1"><FileText className="h-3.5 w-3.5" /> {selectedReport.documentId?.fileName}</span>
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
                <div className="lg:col-span-4 flex flex-col items-center justify-center p-5 rounded-2xl border border-gray-900 bg-gray-950/30">
                  <div className="mb-3 text-center space-y-0.5">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1 justify-center"><ShieldAlert className="h-3.5 w-3.5 text-red-400" /> Plagiarism Index</h3>
                    <p className="text-[9px] text-gray-500">Consensus overlap from 5 independent layers</p>
                  </div>
                  <CircularGauge score={selectedReport.scores.plagiarismIndex} size="large" label="Plagiarism Index" />
                </div>

                {/* Perspective Small Circles */}
                <div className="lg:col-span-8 p-5 rounded-2xl border border-gray-900 bg-gray-950/30 space-y-4">
                  <div className="border-b border-gray-900 pb-2">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">Independent Matching Layers</h3>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                    <CircularGauge score={selectedReport.scores.exactMatchScore} size="small" label="Verbatim Copy" />
                    <CircularGauge score={selectedReport.scores.sequenceScore} size="small" label="Edit Distance" />
                    <CircularGauge score={selectedReport.scores.paraphraseScore} size="small" label="Synonym Flips" />
                    <CircularGauge score={selectedReport.scores.semanticScore} size="small" label="Semantic Overlap" />
                    <CircularGauge score={selectedReport.scores.aiRewriteScore} size="small" label="AI Rewrite Prob" />
                  </div>
                </div>
              </div>

              {/* Tabs Navigation */}
              <div className="flex border-b border-gray-900 text-xs">
                {(['sources', 'highlight', 'raw'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-3 font-bold uppercase tracking-wider border-b-2 transition ${
                      activeTab === tab 
                        ? 'border-emerald-500 text-emerald-400' 
                        : 'border-transparent text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {tab === 'sources' && 'Matching Sources'}
                    {tab === 'highlight' && 'Turnitin-Style Highlights'}
                    {tab === 'raw' && 'Full Markdown'}
                  </button>
                ))}
              </div>

              {/* Tab Panels */}
              <div className="min-h-[300px]">
                
                {/* 1. MATCHING SOURCES */}
                {activeTab === 'sources' && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="space-y-4"
                  >
                    {selectedReport.matches.length === 0 ? (
                      <div className="rounded-xl border border-gray-900 bg-gray-950/30 p-8 text-center max-w-xl mx-auto space-y-3">
                        <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto" />
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider">High Document Uniqueness</h3>
                        <p className="text-xs text-gray-400">
                          This document does not match any registered reference files in V-Trace registry.
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {selectedReport.matches.map((match, idx) => (
                          <div 
                            key={idx}
                            className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 space-y-3"
                          >
                            <div className="flex justify-between items-start border-b border-gray-900/60 pb-2">
                              <div>
                                <span className="text-[9px] text-gray-500 font-mono">MATCHING DOCUMENT INDEX {idx + 1}</span>
                                <h4 className="font-bold text-white text-sm">{match.matchedTitle}</h4>
                              </div>
                              <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-bold ${
                                match.similarityScore >= 40 ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                                'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              }`}>
                                {match.similarityScore}% Similarity
                              </span>
                            </div>

                            <div className="space-y-2.5">
                              {match.matchingTextSegments.map((seg, sIdx) => (
                                <div key={sIdx} className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 rounded-lg border border-gray-900 bg-gray-950/40 text-xs">
                                  <div className="space-y-1">
                                    <span className="text-[9px] font-mono text-gray-500 uppercase">Your Document Segment</span>
                                    <p className="text-gray-300 font-serif">"{seg.originalSegment}"</p>
                                  </div>
                                  <div className="space-y-1 border-t md:border-t-0 md:border-l border-gray-900/60 pt-2 md:pt-0 md:pl-3">
                                    <div className="flex justify-between items-center mb-1">
                                      <span className="text-[9px] font-mono text-gray-500 uppercase">Source Match Segment</span>
                                      <span className={`px-1.5 py-0.5 rounded font-mono text-[8px] uppercase tracking-wider font-extrabold ${
                                        seg.matchType === 'exact' ? 'bg-red-500/10 text-red-400 border border-red-500/25' :
                                        seg.matchType === 'near-match' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/25' :
                                        'bg-purple-500/10 text-purple-400 border border-purple-500/25'
                                      }`}>
                                        {seg.matchType}
                                      </span>
                                    </div>
                                    <p className="text-gray-400 font-serif">"{seg.sourceSegment}"</p>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </motion.div>
                )}

                {/* 2. TURNITIN-STYLE HIGHLIGHTS */}
                {activeTab === 'highlight' && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="rounded-xl border border-gray-900 bg-gray-950/40 p-6 shadow-inner space-y-4"
                  >
                    <div className="flex flex-wrap items-center justify-between border-b border-gray-900 pb-2.5 gap-2 text-[10px] uppercase font-mono font-bold text-gray-500">
                      <span>Document Interactive Text Viewer</span>
                      <div className="flex gap-4">
                        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-red-500" /> Verbatim</span>
                        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-500" /> Near-Match</span>
                        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-indigo-500" /> Synonym Swaps</span>
                        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-purple-500" /> Semantic</span>
                      </div>
                    </div>

                    <div className="p-4 bg-gray-950 border border-gray-900 rounded-lg">
                      {renderHighlightedDocument()}
                    </div>
                  </motion.div>
                )}

                {/* 3. RAW MARKDOWN REPORT */}
                {activeTab === 'raw' && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="rounded-xl border border-gray-900 bg-gray-950/40 p-6 shadow-inner max-w-3xl mx-auto"
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
