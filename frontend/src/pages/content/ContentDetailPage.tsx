import { Link, useParams } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { 
  ArrowLeft, Calendar, FileText, CheckCircle2, AlertTriangle, 
  XCircle, Clock, Hash, Database, Tag, ShieldCheck, User, Loader2
} from 'lucide-react';
import apiClient from '../../lib/axios';
import type { Content } from '../../types';
import { ProvenanceGraph, type GraphNode, type GraphLink } from '../../components/content/ProvenanceGraph';

interface AnalysisResponse {
  analysis: {
    status: 'pending' | 'completed' | 'failed';
    metadataRiskScore: number;
    integrityVerificationScore: number;
    verificationConfidence: number;
    metadataFindings: string;
    analysisLogs: string[];
    forensicReport: string;
    processedAt?: string;
    errorMessage?: string;
  };
}

function renderInlineMarkdown(text: string) {
  const codeParts = text.split('`');
  return codeParts.map((part, i) => {
    if (i % 2 === 1) {
      return (
        <code key={i} className="px-1.5 py-0.5 rounded bg-gray-950 border border-gray-800 text-[11px] font-mono text-emerald-400">
          {part}
        </code>
      );
    }
    const boldParts = part.split('**');
    return boldParts.map((subPart, j) => {
      if (j % 2 === 1) {
        return <strong key={j} className="text-white font-semibold">{subPart}</strong>;
      }
      return subPart;
    });
  });
}

function ForensicReportRenderer({ markdown }: { markdown: string }) {
  if (!markdown) return null;

  const lines = markdown.split('\n');

  return (
    <div className="space-y-4 text-gray-300 text-sm leading-relaxed">
      {lines.map((line, index) => {
        const trimmed = line.trim();

        if (trimmed.startsWith('# ')) {
          return (
            <h1 key={index} className="text-lg font-bold text-white border-b border-gray-800 pb-2 mb-4 mt-6">
              {trimmed.substring(2)}
            </h1>
          );
        }

        if (trimmed.startsWith('## ')) {
          return (
            <h2 key={index} className="text-sm font-semibold text-gray-200 mt-6 mb-2 flex items-center gap-2">
              {trimmed.substring(3)}
            </h2>
          );
        }

        if (trimmed.startsWith('* ')) {
          const content = trimmed.substring(2);
          return (
            <li key={index} className="list-none ml-4 relative pl-5 before:content-['•'] before:absolute before:left-0 before:text-emerald-500 font-normal">
              {renderInlineMarkdown(content)}
            </li>
          );
        }

        if (trimmed.startsWith('❌') || trimmed.startsWith('⚠️') || trimmed.startsWith('✅')) {
          let alertClass = 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400';
          if (trimmed.includes('CRITICAL FLAG') || trimmed.startsWith('❌')) {
            alertClass = 'bg-red-500/5 border-red-500/20 text-red-400';
          } else if (trimmed.includes('WARNING') || trimmed.startsWith('⚠️')) {
            alertClass = 'bg-amber-500/5 border-amber-500/20 text-amber-400';
          }

          return (
            <div key={index} className={`rounded-xl border p-4 my-4 backdrop-blur-sm ${alertClass}`}>
              {renderInlineMarkdown(trimmed)}
            </div>
          );
        }

        if (trimmed.length > 0) {
          return <p key={index}>{renderInlineMarkdown(trimmed)}</p>;
        }

        return <div key={index} className="h-2" />;
      })}
    </div>
  );
}

interface SingleContentResponse {
  content: Content & {
    description?: string;
    merkleRoot?: string;
    chunkHashes?: string[];
    fileSize?: number;
    mimeType?: string;
    tags?: string[];
    isPublic: boolean;
    createdAt: string;
    verifiedAt?: string;
    verifiedBy?: { name: string };
    metadata?: {
      storageUrl?: string;
      storageProvider?: string;
      storageKey?: string;
      flagReason?: string;
      [key: string]: any;
    };
  };
}

function renderMediaPlayer(contentType: string, url: string, title: string) {
  switch (contentType) {
    case 'video':
      return (
        <video 
          src={url} 
          controls 
          className="w-full max-h-[400px] rounded-lg object-contain bg-black border border-gray-900 shadow-md"
        />
      );
    case 'image':
      return (
        <div className="relative group overflow-hidden rounded-lg bg-black/40 flex items-center justify-center w-full">
          <img 
            src={url} 
            alt={title} 
            className="w-full max-h-[400px] rounded-lg object-contain transition-transform duration-300 hover:scale-[1.01] cursor-zoom-in"
          />
        </div>
      );
    case 'audio':
      return (
        <div className="w-full p-4 bg-gray-950/50 rounded-lg border border-gray-800/60 flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs text-gray-400 font-medium font-mono truncate">{title}</span>
          </div>
          <audio 
            src={url} 
            controls 
            className="w-full h-10 accent-emerald-400"
          />
        </div>
      );
    default:
      return (
        <div className="w-full p-6 bg-gray-950/30 rounded-lg border border-gray-800 flex flex-col items-center justify-center gap-3 text-center">
          <FileText className="h-10 w-10 text-gray-600" />
          <div className="space-y-1">
            <span className="text-xs text-gray-300 font-semibold block">{title}</span>
            <span className="text-[10px] text-gray-500 block uppercase tracking-wider">Evidence Document Registry</span>
          </div>
          <a 
            href={url} 
            target="_blank" 
            rel="noopener noreferrer" 
            className="mt-2 rounded-lg bg-gray-800 hover:bg-gray-700 px-4 py-1.5 text-xs font-semibold text-white border border-gray-750 transition"
          >
            Open File in New Tab
          </a>
        </div>
      );
  }
}

function getStatusBadge(status: string) {
  switch (status) {
    case 'verified':
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-3 py-1 text-sm font-semibold text-emerald-400">
          <CheckCircle2 className="h-4 w-4" />
          <span>Verified</span>
        </span>
      );
    case 'flagged':
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 border border-amber-500/20 px-3 py-1 text-sm font-semibold text-amber-400">
          <AlertTriangle className="h-4 w-4" />
          <span>Flagged</span>
        </span>
      );
    case 'rejected':
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/10 border border-red-500/20 px-3 py-1 text-sm font-semibold text-red-400">
          <XCircle className="h-4 w-4" />
          <span>Rejected</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-gray-500/10 border border-gray-500/20 px-3 py-1 text-sm font-semibold text-gray-400">
          <Clock className="h-4 w-4" />
          <span>Pending Audit</span>
        </span>
      );
  }
}

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return 'Unknown Size';
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function ContentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'details' | 'forensic'>('details');

  const { data, isLoading, isError } = useQuery<SingleContentResponse>({
    queryKey: ['content-detail', id],
    queryFn: async () => {
      const response = await apiClient.get<SingleContentResponse>(`/content/${id}`);
      return response.data;
    },
    enabled: Boolean(id),
  });

  const { data: graphData, isLoading: loadingGraph } = useQuery<{ nodes: GraphNode[]; links: GraphLink[] }>({
    queryKey: ['content-provenance', id],
    queryFn: async () => {
      const response = await apiClient.get<{ nodes: GraphNode[]; links: GraphLink[] }>(`/content/${id}/provenance`);
      return response.data;
    },
    enabled: Boolean(id),
  });

  const { data: analysisData } = useQuery<AnalysisResponse>({
    queryKey: ['content-analysis', id],
    queryFn: async () => {
      const response = await apiClient.get<AnalysisResponse>(`/content/${id}/analysis`);
      return response.data;
    },
    refetchInterval: (query) => {
      const status = query.state.data?.analysis?.status;
      return status === 'pending' ? 1500 : false;
    },
    enabled: Boolean(id),
  });

  const analysisStatus = analysisData?.analysis?.status;

  useEffect(() => {
    if (analysisStatus === 'completed') {
      queryClient.invalidateQueries({ queryKey: ['content-detail', id] });
    }
  }, [analysisStatus, id, queryClient]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-40 text-gray-400 space-y-4">
        <div className="h-10 w-10 border-4 border-emerald-400 border-t-transparent rounded-full animate-spin" />
        <span>Retrieving evidence details...</span>
      </div>
    );
  }

  if (isError || !data?.content) {
    return (
      <section className="space-y-6">
        <Link to="/content" className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-white transition">
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Library</span>
        </Link>
        <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-8 text-center text-red-400">
          Evidence item not found or access is restricted.
        </div>
      </section>
    );
  }

  const { content } = data;

  return (
    <section className="space-y-6">
      {/* Header Navigation */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="space-y-2">
          <Link to="/content" className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-white transition">
            <ArrowLeft className="h-4 w-4" />
            <span>Back to Library</span>
          </Link>
          <h1 className="text-3xl font-bold tracking-tight text-white">{content.title}</h1>
        </div>
        <div className="self-start md:self-end">
          {getStatusBadge(content.status)}
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column: Properties & Metadata */}
        <div className="space-y-6 lg:col-span-2">
          {/* Main Card with Tabs */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm space-y-6">
            {/* Tabs Header */}
            <div className="flex border-b border-gray-800 pb-0.5 gap-4">
              <button
                onClick={() => setActiveTab('details')}
                className={`pb-3 text-sm font-semibold transition-colors duration-200 border-b-2 px-1 ${
                  activeTab === 'details'
                    ? 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                General Details
              </button>
              <button
                onClick={() => setActiveTab('forensic')}
                className={`pb-3 text-sm font-semibold transition-colors duration-200 border-b-2 px-1 flex items-center gap-2 ${
                  activeTab === 'forensic'
                    ? 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                <span>Forensic Analysis</span>
                {analysisStatus === 'pending' && (
                  <span className="flex h-2 w-2 relative">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                )}
              </button>
            </div>

            {activeTab === 'details' ? (
              <>
                {content.metadata?.storageUrl && (
                  <div className="rounded-xl border border-gray-800 bg-gray-950/25 overflow-hidden shadow-inner flex items-center justify-center p-2 mb-6">
                    {renderMediaPlayer(content.contentType, content.metadata.storageUrl, content.title)}
                  </div>
                )}

                <div className="space-y-2">
                  <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Description</h2>
                  <p className="text-gray-200 text-sm leading-relaxed">
                    {content.description || 'No description provided for this content.'}
                  </p>
                </div>

                <div className="grid gap-4 sm:grid-cols-2 pt-4 border-t border-gray-800">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-950 text-gray-400 border border-gray-800">
                      <Database className="h-5 w-5" />
                    </div>
                    <div>
                      <span className="text-[10px] text-gray-500 font-medium block">File Info</span>
                      <span className="text-xs text-white block mt-0.5">
                        {formatBytes(content.fileSize)} • {content.mimeType || 'Unknown MIME'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-950 text-gray-400 border border-gray-800">
                      <Calendar className="h-5 w-5" />
                    </div>
                    <div>
                      <span className="text-[10px] text-gray-500 font-medium block">Registration Date</span>
                      <span className="text-xs text-white block mt-0.5">
                        {new Date(content.createdAt).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-950 text-gray-400 border border-gray-800">
                      <User className="h-5 w-5" />
                    </div>
                    <div>
                      <span className="text-[10px] text-gray-500 font-medium block">Registered By</span>
                      <span className="text-xs text-white block mt-0.5">
                        {content.owner?.name || 'Unknown'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-950 text-gray-400 border border-gray-800">
                      <ShieldCheck className="h-5 w-5" />
                    </div>
                    <div>
                      <span className="text-[10px] text-gray-500 font-medium block">Privacy Status</span>
                      <span className="text-xs text-white block mt-0.5">
                        {content.isPublic ? 'Publicly Searchable' : 'Private Access'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Tags Box */}
                {content.tags && content.tags.length > 0 && (
                  <div className="space-y-3 pt-4 border-t border-gray-800">
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
                      <Tag className="h-3.5 w-3.5" />
                      Evidence Tags
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {content.tags.map((tag) => (
                        <span key={tag} className="rounded-md bg-gray-950 border border-gray-800 px-2.5 py-1 text-xs text-gray-300">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="space-y-6 pt-2">
                {/* Status Indicator */}
                {analysisStatus === 'pending' && (
                  <div className="flex items-center gap-3 rounded-xl border border-emerald-500/20 bg-emerald-950/5 p-4 text-emerald-400">
                    <Loader2 className="h-5 w-5 animate-spin text-emerald-400" />
                    <span className="text-sm font-medium">Running native forensic heuristics checks...</span>
                  </div>
                )}

                {analysisStatus === 'failed' && (
                  <div className="flex items-center gap-3 rounded-xl border border-red-500/20 bg-red-950/5 p-4 text-red-400">
                    <XCircle className="h-5 w-5" />
                    <span className="text-sm font-medium">
                      Forensic analysis failed: {analysisData?.analysis?.errorMessage || 'Unknown error'}
                    </span>
                  </div>
                )}

                {analysisStatus === 'completed' && analysisData?.analysis && (
                  <>
                    {/* Risk Grid */}
                    <div className="grid gap-4 sm:grid-cols-3">
                      <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
                        <span className="text-xs text-gray-500 font-medium block">Metadata Risk Score</span>
                        <div className="flex items-baseline gap-2 mt-1">
                          <span className={`text-2xl font-bold ${
                            analysisData.analysis.metadataRiskScore > 70 ? 'text-red-400' :
                            analysisData.analysis.metadataRiskScore > 25 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {analysisData.analysis.metadataRiskScore}%
                          </span>
                          <span className="text-[10px] text-gray-500 font-medium">risk</span>
                        </div>
                        <div className="w-full bg-gray-900 rounded-full h-1.5 mt-3 overflow-hidden">
                          <div 
                            className={`h-1.5 rounded-full ${
                              analysisData.analysis.metadataRiskScore > 70 ? 'bg-red-500' :
                              analysisData.analysis.metadataRiskScore > 25 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${analysisData.analysis.metadataRiskScore}%` }}
                          />
                        </div>
                      </div>

                      <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
                        <span className="text-xs text-gray-500 font-medium block">Integrity Score</span>
                        <div className="flex items-baseline gap-2 mt-1">
                          <span className={`text-2xl font-bold ${
                            analysisData.analysis.integrityVerificationScore < 30 ? 'text-red-400' :
                            analysisData.analysis.integrityVerificationScore < 75 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {analysisData.analysis.integrityVerificationScore}%
                          </span>
                          <span className="text-[10px] text-gray-500 font-medium">score</span>
                        </div>
                        <div className="w-full bg-gray-900 rounded-full h-1.5 mt-3 overflow-hidden">
                          <div 
                            className={`h-1.5 rounded-full ${
                              analysisData.analysis.integrityVerificationScore < 30 ? 'bg-red-500' :
                              analysisData.analysis.integrityVerificationScore < 75 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${analysisData.analysis.integrityVerificationScore}%` }}
                          />
                        </div>
                      </div>

                      <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
                        <span className="text-xs text-gray-500 font-medium block">Confidence</span>
                        <div className="flex items-baseline gap-2 mt-1">
                          <span className={`text-2xl font-bold ${
                            analysisData.analysis.verificationConfidence < 50 ? 'text-red-400' :
                            analysisData.analysis.verificationConfidence < 85 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {analysisData.analysis.verificationConfidence}%
                          </span>
                          <span className="text-[10px] text-gray-500 font-medium">score</span>
                        </div>
                        <div className="w-full bg-gray-900 rounded-full h-1.5 mt-3 overflow-hidden">
                          <div 
                            className={`h-1.5 rounded-full ${
                              analysisData.analysis.verificationConfidence < 50 ? 'bg-red-500' :
                              analysisData.analysis.verificationConfidence < 85 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${analysisData.analysis.verificationConfidence}%` }}
                          />
                        </div>
                      </div>
                    </div>

                    {/* Classified Metadata Findings */}
                    <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 flex justify-between items-center">
                      <div>
                        <span className="text-xs text-gray-500 font-medium block">Metadata Findings</span>
                        <span className="text-sm text-white font-semibold block mt-1 uppercase tracking-wider font-mono">
                          {analysisData.analysis.metadataFindings}
                        </span>
                      </div>
                      <div className="rounded-lg bg-gray-900 border border-gray-800 px-3 py-1.5 text-xs text-gray-400">
                        {analysisData.analysis.metadataRiskScore > 75 ? (
                          <span className="text-red-400 font-semibold flex items-center gap-1.5">
                            <AlertTriangle className="h-4 w-4" />
                            Flagged Anomaly
                          </span>
                        ) : (
                          <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                            <CheckCircle2 className="h-4 w-4" />
                            Verified Safe
                          </span>
                        )}
                      </div>
                    </div>
                  </>
                )}

                {/* Diagnostic Pipeline Logs */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Analysis Logs</h3>
                  <div className="rounded-xl border border-gray-800 bg-black p-4 font-mono text-[11px] leading-relaxed text-gray-400 max-h-60 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
                    {analysisData?.analysis?.analysisLogs?.map((log, idx) => {
                      const isWarning = log.includes('Warning:');
                      const isError = log.includes('Error:');
                      const isSuccess = log.includes('completed successfully') || log.includes('passed') || log.includes('VALID');
                      
                      let textClass = 'text-gray-400';
                      if (isWarning) textClass = 'text-amber-400';
                      else if (isError) textClass = 'text-red-400';
                      else if (isSuccess) textClass = 'text-emerald-400';
                      
                      return (
                        <div key={idx} className="flex gap-2">
                          <span className="text-gray-600 select-none">&gt;</span>
                          <span className={textClass}>{log}</span>
                        </div>
                      );
                    })}
                    {analysisStatus === 'pending' && (
                      <div className="flex gap-2 items-center">
                        <span className="text-gray-600 select-none">&gt;</span>
                        <span className="text-emerald-400 animate-pulse font-bold">▋</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Markdown Report (visible if completed) */}
                {analysisStatus === 'completed' && analysisData?.analysis?.forensicReport && (
                  <div className="space-y-2 pt-4 border-t border-gray-800">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Analysis Summary</h3>
                    <div className="rounded-xl border border-gray-800 bg-gray-950 p-6">
                      <ForensicReportRenderer markdown={analysisData.analysis.forensicReport} />
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Verification Audit Log */}
          {content.status === 'verified' && (
            <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/5 p-6 backdrop-blur-sm space-y-4">
              <h2 className="text-sm font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5" />
                Verification Log
              </h2>
              <div className="text-sm text-gray-300 space-y-2">
                <p>This content was analyzed and officially verified as authentic.</p>
                <div className="grid gap-2 sm:grid-cols-2 pt-2 text-xs text-gray-400">
                  <span>Verified By: {content.verifiedBy?.name || 'Platform Audit'}</span>
                  <span>Date: {content.verifiedAt ? new Date(content.verifiedAt).toLocaleString() : 'N/A'}</span>
                </div>
              </div>
            </div>
          )}

          {/* Trust Network Graph section */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm space-y-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              Evidence Network Flow
            </h2>
            
            {loadingGraph ? (
              <div className="flex justify-center items-center py-10 text-gray-500 text-xs gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />
                <span>Mapping evidence flow...</span>
              </div>
            ) : graphData && graphData.nodes.length > 1 ? (
              <ProvenanceGraph 
                nodes={graphData.nodes} 
                links={graphData.links} 
                targetId={content._id} 
              />
            ) : (
              <div className="text-center py-6 text-gray-500 text-xs">
                This item is an independent root record (no derived files or parent records linked).
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Cryptographic Proofs */}
        <div className="space-y-6">
          <div className="rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm space-y-5">
            <h2 className="text-lg font-semibold text-white">Cryptographic Proofs</h2>

            <div className="space-y-4 text-sm">
              <div className="space-y-1">
                <span className="text-xs text-gray-500 font-medium flex items-center gap-1">
                  <Hash className="h-3.5 w-3.5 text-gray-500" />
                  Digital Signature (SHA-256)
                </span>
                <div className="rounded-lg bg-gray-950 p-3 font-mono text-[11px] break-all text-gray-300 border border-gray-800 select-all">
                  {content.originalHash}
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-xs text-gray-500 font-medium flex items-center gap-1">
                  <FileText className="h-3.5 w-3.5 text-gray-500" />
                  Verification Key (Merkle Root)
                </span>
                <div className="rounded-lg bg-gray-950 p-3 font-mono text-[11px] break-all text-emerald-400 border border-emerald-500/20 select-all">
                  {content.merkleRoot || 'N/A'}
                </div>
              </div>
            </div>

            {/* Chunk Hashes List */}
            {content.chunkHashes && content.chunkHashes.length > 0 && (
              <div className="space-y-3 pt-4 border-t border-gray-800">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Leaves ({content.chunkHashes.length} Chunks)
                  </h3>
                  <span className="text-[10px] text-gray-500 bg-gray-950 px-2 py-0.5 rounded border border-gray-800">1MB chunks</span>
                </div>
                
                <div className="max-h-60 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                  {content.chunkHashes.map((hash, idx) => (
                    <div key={idx} className="flex gap-2 items-center rounded bg-gray-950 p-2 border border-gray-800 text-[10px] font-mono">
                      <span className="text-emerald-500 font-bold bg-emerald-500/5 border border-emerald-500/10 px-1 rounded min-w-[20px] text-center">
                        {idx}
                      </span>
                      <span className="truncate text-gray-400 select-all">{hash}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export default ContentDetailPage;
