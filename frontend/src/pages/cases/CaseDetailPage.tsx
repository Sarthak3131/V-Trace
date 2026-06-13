import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { 
  Plus, Loader2, User, 
  CheckCircle, AlertOctagon, X,
  Briefcase, ShieldAlert, ArrowLeft, Send, MessageSquare, History, FileSymlink, Trash2
} from 'lucide-react';
import apiClient from '../../lib/axios';
import { useAuthStore } from '../../store/authStore';

interface CaseNote {
  _id: string;
  text: string;
  createdBy: {
    name: string;
    role: string;
  };
  createdAt: string;
}

interface CaseHistory {
  _id: string;
  action: string;
  details?: string;
  performedBy: {
    name: string;
    role: string;
  };
  performedAt: string;
}

interface ContentItem {
  _id: string;
  title: string;
  contentType: string;
  status: string;
  originalHash: string;
}

interface Case {
  _id: string;
  title: string;
  description?: string;
  status: 'open' | 'in-progress' | 'resolved' | 'closed';
  severity: 'low' | 'medium' | 'high' | 'critical';
  assignedTo?: {
    _id: string;
    name: string;
    email: string;
    role: string;
  };
  createdBy: {
    _id: string;
    name: string;
    email: string;
    role: string;
  };
  evidence: ContentItem[];
  notes: CaseNote[];
  history: CaseHistory[];
  createdAt: string;
  updatedAt: string;
}

interface UserSummary {
  _id: string;
  name: string;
  email: string;
  role: string;
}

interface ContentSummary {
  _id: string;
  title: string;
  contentType: string;
  status: string;
}

function getStatusBadge(status: string) {
  switch (status) {
    case 'open':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-0.5 text-xs font-semibold text-emerald-400">
          <CheckCircle className="h-3 w-3" />
          <span>Open</span>
        </span>
      );
    case 'in-progress':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-blue-500/10 border border-blue-500/20 px-2.5 py-0.5 text-xs font-semibold text-blue-400">
          <Loader2 className="h-3 w-3 animate-spin" />
          <span>In Progress</span>
        </span>
      );
    case 'resolved':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-purple-500/10 border border-purple-500/20 px-2.5 py-0.5 text-xs font-semibold text-purple-400">
          <CheckCircle className="h-3 w-3" />
          <span>Resolved</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-gray-500/10 border border-gray-500/20 px-2.5 py-0.5 text-xs font-semibold text-gray-400">
          <span>Closed</span>
        </span>
      );
  }
}

function getSeverityBadge(severity: string) {
  switch (severity) {
    case 'critical':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 border border-red-500/20 px-2.5 py-0.5 text-xs font-semibold text-red-400">
          <AlertOctagon className="h-3 w-3" />
          <span>Critical</span>
        </span>
      );
    case 'high':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-orange-500/10 border border-orange-500/20 px-2.5 py-0.5 text-xs font-semibold text-orange-400">
          <ShieldAlert className="h-3 w-3" />
          <span>High</span>
        </span>
      );
    case 'medium':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 border border-amber-500/20 px-2.5 py-0.5 text-xs font-semibold text-amber-400">
          <span>Medium</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-gray-500/10 border border-gray-500/20 px-2.5 py-0.5 text-xs font-semibold text-gray-400">
          <span>Low</span>
        </span>
      );
  }
}

function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const currentUser = useAuthStore((state) => state.user);

  // UI state
  const [noteText, setNoteText] = useState('');
  const [evidenceModalOpen, setEvidenceModalOpen] = useState(false);
  const [isEditingMeta, setIsEditingMeta] = useState(false);

  // Edit meta form states
  const [status, setStatus] = useState<'open' | 'in-progress' | 'resolved' | 'closed'>('open');
  const [severity, setSeverity] = useState<'low' | 'medium' | 'high' | 'critical'>('medium');
  const [assignedTo, setAssignedTo] = useState('');

  // Fetch Case Details
  const { data: caseData, isLoading, isError } = useQuery<{ case: Case }>({
    queryKey: ['case-details', id],
    queryFn: async () => {
      const res = await apiClient.get<{ case: Case }>(`/cases/${id}`);
      // Initialize edit fields
      setStatus(res.data.case.status);
      setSeverity(res.data.case.severity);
      setAssignedTo(res.data.case.assignedTo?._id || '');
      return res.data;
    }
  });

  // Query: Fetch users (to reassign)
  const { data: usersData } = useQuery<{ users: UserSummary[] }>({
    queryKey: ['investigators-list-details'],
    queryFn: async () => {
      const res = await apiClient.get<{ users: UserSummary[] }>('/auth/users');
      return res.data;
    },
    enabled: isEditingMeta
  });

  // Query: Fetch available user evidence (to link)
  const { data: contentData } = useQuery<{ contents: ContentSummary[] }>({
    queryKey: ['user-content-brief-details'],
    queryFn: async () => {
      const res = await apiClient.get<{ contents: ContentSummary[] }>('/content/me?limit=100');
      return res.data;
    },
    enabled: evidenceModalOpen
  });

  // Mutation: Add note
  const addNoteMutation = useMutation({
    mutationFn: async (text: string) => {
      const res = await apiClient.post<{ case: Case }>(`/cases/${id}/notes`, { text });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case-details', id] });
      setNoteText('');
    }
  });

  // Mutation: Update meta
  const updateMetaMutation = useMutation({
    mutationFn: async (payload: { status: string; severity: string; assignedTo: string }) => {
      const res = await apiClient.patch<{ case: Case }>(`/cases/${id}`, payload);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case-details', id] });
      setIsEditingMeta(false);
    }
  });

  // Mutation: Link / Unlink evidence
  const linkEvidenceMutation = useMutation({
    mutationFn: async (payload: { contentId: string; action: 'link' | 'unlink' }) => {
      const res = await apiClient.post<{ case: Case }>(`/cases/${id}/evidence`, payload);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case-details', id] });
      setEvidenceModalOpen(false);
    }
  });

  const handleNoteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (noteText.trim().length === 0) return;
    addNoteMutation.mutate(noteText);
  };

  const handleMetaUpdateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateMetaMutation.mutate({
      status,
      severity,
      assignedTo: assignedTo || ''
    });
  };

  const isPrivileged = currentUser?.role === 'admin' || currentUser?.role === 'moderator';

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-40 gap-3">
        <Loader2 className="h-10 w-10 text-emerald-400 animate-spin" />
        <p className="text-gray-400 text-sm">Loading case details...</p>
      </div>
    );
  }

  if (isError || !caseData) {
    return (
      <div className="space-y-4 max-w-lg mx-auto py-10">
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center text-red-400">
          Access denied or Case records not found. You must be the creator, assignee, or a moderator to inspect this case.
        </div>
        <Link to="/cases" className="flex items-center justify-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300">
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Return to Registry</span>
        </Link>
      </div>
    );
  }

  const kase = caseData.case;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-gray-800 pb-4">
        <div className="space-y-1">
          <Link to="/cases" className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-emerald-400 transition-colors mb-2">
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>All Investigation Cases</span>
          </Link>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
            <Briefcase className="h-7 w-7 text-emerald-400" />
            <span>{kase.title}</span>
          </h1>
          <p className="text-xs text-gray-500">
            Opened on {new Date(kase.createdAt).toLocaleString()} by {kase.createdBy.name} ({kase.createdBy.role})
          </p>
        </div>
        
        {isPrivileged && (
          <button
            onClick={() => setIsEditingMeta(!isEditingMeta)}
            className="rounded-lg bg-gray-800 border border-gray-700 px-4 py-2 text-sm font-semibold text-white transition hover:bg-gray-700 self-start sm:self-center"
          >
            {isEditingMeta ? 'Cancel Edit' : 'Edit Case Properties'}
          </button>
        )}
      </div>

      {/* Editing Metadata Panel */}
      {isEditingMeta && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-gray-800 bg-gray-900/40 p-4"
        >
          <form onSubmit={handleMetaUpdateSubmit} className="grid grid-cols-1 sm:grid-cols-4 gap-4 items-end">
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-gray-500 uppercase">Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as any)}
                className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-white focus:outline-none"
              >
                <option value="open">Open</option>
                <option value="in-progress">In Progress</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-gray-500 uppercase">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as any)}
                className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-white focus:outline-none"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-gray-500 uppercase">Investigator Assigned</label>
              <select
                value={assignedTo}
                onChange={(e) => setAssignedTo(e.target.value)}
                className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-white focus:outline-none"
              >
                <option value="">Unassigned</option>
                {usersData?.users.map((u) => (
                  <option key={u._id} value={u._id}>
                    {u.name} ({u.role})
                  </option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              disabled={updateMetaMutation.isPending}
              className="rounded-lg bg-emerald-400 px-4 py-2 text-xs font-semibold text-gray-900 hover:bg-emerald-300 disabled:opacity-50"
            >
              {updateMetaMutation.isPending ? 'Saving...' : 'Update Properties'}
            </button>
          </form>
        </motion.div>
      )}

      {/* Overview Details Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Left Column: Scope & Meta */}
        <div className="md:col-span-2 space-y-6">
          <div className="rounded-xl border border-gray-800 bg-gray-900/10 p-5 space-y-4">
            <h2 className="text-lg font-bold text-white">Case Overview & Scope</h2>
            <p className="text-sm text-gray-300 whitespace-pre-wrap leading-relaxed">
              {kase.description || 'No detailed scope or incident overview has been provided for this case.'}
            </p>
            <div className="flex flex-wrap gap-4 pt-3 border-t border-gray-900 text-xs">
              <div>
                <span className="block text-gray-500 font-semibold mb-1">STATUS</span>
                {getStatusBadge(kase.status)}
              </div>
              <div>
                <span className="block text-gray-500 font-semibold mb-1">SEVERITY</span>
                {getSeverityBadge(kase.severity)}
              </div>
              <div>
                <span className="block text-gray-500 font-semibold mb-1">ASSIGNED INVESTIGATOR</span>
                {kase.assignedTo ? (
                  <span className="inline-flex items-center gap-1 rounded bg-gray-800 px-2 py-0.5 font-medium text-gray-300">
                    <User className="h-3 w-3 text-emerald-400" />
                    <span>{kase.assignedTo.name} ({kase.assignedTo.role})</span>
                  </span>
                ) : (
                  <span className="text-gray-500 italic">No investigator assigned</span>
                )}
              </div>
            </div>
          </div>

          {/* Linked Evidence Files */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <FileSymlink className="h-5 w-5 text-emerald-400" />
                <span>Linked Evidence Files ({kase.evidence.length})</span>
              </h2>
              <button
                onClick={() => setEvidenceModalOpen(true)}
                className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-500/20 flex items-center gap-1"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Link Evidence</span>
              </button>
            </div>

            {kase.evidence.length === 0 ? (
              <div className="rounded-xl border border-dashed border-gray-800 bg-gray-950/20 p-8 text-center text-gray-500 text-xs italic">
                No active evidence files have been linked to this case yet. Link registered files from your library to begin analysis compilation.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {kase.evidence.map((item) => (
                  <div key={item._id} className="rounded-xl border border-gray-800 bg-gray-950 p-4 hover:border-gray-700 transition flex flex-col justify-between">
                    <div>
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-xs font-semibold text-white truncate max-w-[80%]">{item.title}</span>
                        <span className={`text-[10px] rounded px-1.5 py-0.5 capitalize ${
                          item.status === 'verified' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                          item.status === 'flagged' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                          'bg-gray-800 text-gray-400'
                        }`}>{item.status}</span>
                      </div>
                      <p className="text-[10px] text-gray-500 font-mono mt-2 truncate">Hash: {item.originalHash}</p>
                      <p className="text-[10px] text-gray-400 capitalize mt-1">Type: {item.contentType}</p>
                    </div>

                    <div className="flex items-center justify-between border-t border-gray-900 mt-4 pt-3">
                      <Link
                        to={`/content/${item._id}`}
                        className="text-xs text-emerald-400 hover:underline"
                      >
                        Inspect Anomaly Reports
                      </Link>
                      <button
                        onClick={() => linkEvidenceMutation.mutate({ contentId: item._id, action: 'unlink' })}
                        className="text-gray-500 hover:text-red-400"
                        title="Unlink from case"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Notes and Investigator Logs */}
          <div className="space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <MessageSquare className="h-5 w-5 text-emerald-400" />
              <span>Case Notes ({kase.notes.length})</span>
            </h2>

            {/* Note Input */}
            <form onSubmit={handleNoteSubmit} className="flex gap-2">
              <input
                type="text"
                required
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                placeholder="Log a research note, evidence finding, or verification update..."
                className="flex-1 rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-2 text-sm text-white focus:outline-none"
              />
              <button
                type="submit"
                disabled={addNoteMutation.isPending || noteText.trim().length === 0}
                className="rounded-lg bg-emerald-400 p-2 text-gray-900 hover:bg-emerald-300 disabled:opacity-50"
              >
                {addNoteMutation.isPending ? <Loader2 className="h-5 w-5 animate-spin" /> : <Send className="h-5 w-5" />}
              </button>
            </form>

            {/* Notes List */}
            <div className="space-y-3">
              {kase.notes.length === 0 ? (
                <p className="text-xs text-gray-500 italic">No notes logged yet.</p>
              ) : (
                [...kase.notes].reverse().map((note) => (
                  <div key={note._id} className="rounded-lg border border-gray-900 bg-gray-950 p-3.5 space-y-1">
                    <div className="flex items-center justify-between text-[10px] text-gray-500">
                      <span className="font-semibold text-gray-300">{note.createdBy.name} ({note.createdBy.role})</span>
                      <span>{new Date(note.createdAt).toLocaleString()}</span>
                    </div>
                    <p className="text-xs text-gray-200">{note.text}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Case History Timeline */}
        <div className="space-y-4">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <History className="h-5 w-5 text-emerald-400" />
            <span>Case History Timeline</span>
          </h2>
          
          <div className="relative border-l border-gray-800 pl-4 space-y-6">
            {kase.history.map((log) => (
              <div key={log._id} className="relative space-y-1">
                {/* Circle marker */}
                <div className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-emerald-400 border border-gray-950" />
                
                <div className="flex items-center justify-between text-[10px] text-gray-500">
                  <span className="font-semibold text-gray-300 uppercase tracking-wider">{log.action.replace('-', ' ')}</span>
                  <span>{new Date(log.performedAt).toLocaleDateString()}</span>
                </div>
                {log.details && (
                  <p className="text-xs text-gray-400">{log.details}</p>
                )}
                <p className="text-[9px] text-gray-500">by {log.performedBy.name}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Link Evidence Dialog */}
      {evidenceModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="text-lg font-bold text-white">Link Content Evidence</h3>
              <button onClick={() => setEvidenceModalOpen(false)} className="text-gray-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="rounded-lg border border-gray-800 bg-gray-900/30 max-h-60 overflow-y-auto divide-y divide-gray-900 p-2 space-y-1">
              {contentData?.contents && contentData.contents.length === 0 ? (
                <p className="text-xs text-gray-500 italic p-3 text-center">No registered content available to link.</p>
              ) : (
                contentData?.contents
                  .filter(c => !kase.evidence.some(e => e._id === c._id))
                  .map((item) => (
                    <div 
                      key={item._id} 
                      onClick={() => linkEvidenceMutation.mutate({ contentId: item._id, action: 'link' })}
                      className="flex items-center justify-between p-2 rounded-lg cursor-pointer hover:bg-emerald-500/10 border border-transparent hover:border-emerald-500/30 transition-all"
                    >
                      <div className="flex flex-col">
                        <span className="text-xs font-semibold text-white">{item.title}</span>
                        <span className="text-[10px] text-gray-500 capitalize">{item.contentType} • {item.status}</span>
                      </div>
                      <span className="text-[10px] text-emerald-400 font-semibold">Link asset</span>
                    </div>
                  ))
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setEvidenceModalOpen(false)}
                className="rounded-lg border border-gray-800 px-4 py-2 text-xs font-semibold text-gray-400 hover:text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default CaseDetailPage;
