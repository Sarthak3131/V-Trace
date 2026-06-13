import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Folder, Plus, Loader2, Calendar, User, 
  CheckCircle, AlertOctagon, X, Search,
  Briefcase, ShieldAlert
} from 'lucide-react';
import apiClient from '../../lib/axios';

interface CaseNote {
  _id: string;
  text: string;
  createdBy: {
    name: string;
    role: string;
  };
  createdAt: string;
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
  evidence: string[];
  notes: CaseNote[];
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

function CaseListPage() {
  const queryClient = useQueryClient();
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  // Form states
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<'low' | 'medium' | 'high' | 'critical'>('medium');
  const [assignedTo, setAssignedTo] = useState('');
  const [selectedEvidence, setSelectedEvidence] = useState<string[]>([]);

  // Query: Fetch cases list
  const { data: casesData, isLoading, isError } = useQuery<{ cases: Case[] }>({
    queryKey: ['cases-list', statusFilter, severityFilter],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      const res = await apiClient.get<{ cases: Case[] }>('/cases', { params });
      return res.data;
    }
  });

  // Query: Fetch users (to assign)
  const { data: usersData } = useQuery<{ users: UserSummary[] }>({
    queryKey: ['investigators-list'],
    queryFn: async () => {
      const res = await apiClient.get<{ users: UserSummary[] }>('/auth/users');
      return res.data;
    },
    enabled: createModalOpen
  });

  // Query: Fetch available user evidence (to link)
  const { data: contentData } = useQuery<{ contents: ContentSummary[] }>({
    queryKey: ['user-content-brief'],
    queryFn: async () => {
      // Fetch user's own content briefly
      const res = await apiClient.get<{ contents: ContentSummary[] }>('/content/me?limit=100');
      return res.data;
    },
    enabled: createModalOpen
  });

  // Mutation: Create Case
  const createMutation = useMutation({
    mutationFn: async (payload: { title: string; description: string; severity: string; assignedTo?: string; evidence?: string[] }) => {
      const res = await apiClient.post<{ case: Case }>('/cases', payload);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases-list'] });
      setTitle('');
      setDescription('');
      setSeverity('medium');
      setAssignedTo('');
      setSelectedEvidence([]);
      setCreateModalOpen(false);
    }
  });

  const handleCreateCaseSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (title.trim().length < 3) return;

    createMutation.mutate({
      title,
      description,
      severity,
      assignedTo: assignedTo || undefined,
      evidence: selectedEvidence
    });
  };

  const toggleEvidenceSelect = (id: string) => {
    setSelectedEvidence((prev) => 
      prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
            <Briefcase className="h-7 w-7 text-emerald-400" />
            <span>Case Management</span>
          </h1>
          <p className="text-gray-400">Organize and coordinate forensic evidence files inside structured investigations.</p>
        </div>
        <button
          onClick={() => setCreateModalOpen(true)}
          className="rounded-lg bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-gray-900 transition hover:bg-emerald-300 flex items-center gap-1.5 self-start sm:self-center"
        >
          <Plus className="h-4 w-4" />
          <span>Open Investigation Case</span>
        </button>
      </div>

      {/* Filter and Sort Toolbar */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-gray-800 bg-gray-900/30 p-4">
        <div className="flex items-center gap-1.5 text-sm text-gray-400 pr-2 border-r border-gray-800">
          <Search className="h-4 w-4 text-gray-500" />
          <span>Filters:</span>
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 focus:border-emerald-500/50 focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in-progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 focus:border-emerald-500/50 focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <Loader2 className="h-10 w-10 text-emerald-400 animate-spin" />
          <p className="text-gray-400 text-sm">Loading cases...</p>
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center text-red-400">
          Failed to retrieve cases. Please check your credentials or refresh the page.
        </div>
      ) : casesData && casesData.cases.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900/10 p-12 text-center text-gray-400 flex flex-col items-center gap-3">
          <Folder className="h-10 w-10 text-gray-600" />
          <p>No active investigation cases matching the selected filters were found.</p>
          <button
            onClick={() => setCreateModalOpen(true)}
            className="mt-2 rounded-lg bg-gray-800 px-4 py-2 text-xs font-semibold text-white hover:bg-gray-700"
          >
            Create Your First Case
          </button>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-950">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-gray-400">
              <thead className="bg-gray-900/50 text-xs uppercase text-gray-300 border-b border-gray-800">
                <tr>
                  <th className="px-6 py-4">Title</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Severity</th>
                  <th className="px-6 py-4">Assigned Investigator</th>
                  <th className="px-6 py-4">Evidence linked</th>
                  <th className="px-6 py-4">Opened Date</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-900">
                {casesData?.cases.map((kase) => (
                  <tr key={kase._id} className="hover:bg-gray-900/20 transition-colors">
                    <td className="px-6 py-4 font-medium text-white max-w-xs truncate">
                      <Link to={`/cases/${kase._id}`} className="hover:text-emerald-400 transition-colors">
                        {kase.title}
                      </Link>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">{getStatusBadge(kase.status)}</td>
                    <td className="px-6 py-4 whitespace-nowrap">{getSeverityBadge(kase.severity)}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {kase.assignedTo ? (
                        <span className="flex items-center gap-1.5 text-xs text-gray-300">
                          <User className="h-3 w-3 text-emerald-400" />
                          <span>{kase.assignedTo.name}</span>
                        </span>
                      ) : (
                        <span className="text-xs text-gray-500 italic">Unassigned</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-300">
                      {kase.evidence.length} files
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-500">
                      <span className="flex items-center gap-1">
                        <Calendar className="h-3.5 w-3.5" />
                        <span>{new Date(kase.createdAt).toLocaleDateString()}</span>
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right whitespace-nowrap">
                      <Link
                        to={`/cases/${kase._id}`}
                        className="rounded bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 text-xs font-semibold text-emerald-400 transition hover:bg-emerald-500/20"
                      >
                        Inspect Case
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Case Creation Modal */}
      <AnimatePresence>
        {createModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-xl rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto"
            >
              <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  <Briefcase className="h-5 w-5 text-emerald-400" />
                  <span>Open Investigation Case</span>
                </h2>
                <button
                  onClick={() => setCreateModalOpen(false)}
                  className="text-gray-400 hover:text-white"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <form onSubmit={handleCreateCaseSubmit} className="space-y-4">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-gray-400 uppercase">Case Title</label>
                  <input
                    type="text"
                    required
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g. Tampered Video Evidence Review"
                    className="w-full rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-2.5 text-sm text-white focus:border-emerald-500/50 focus:outline-none"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-gray-400 uppercase">Description / Scope</label>
                  <textarea
                    rows={3}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Provide overview details, incident notes, or legal tracking references..."
                    className="w-full rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-2.5 text-sm text-white focus:border-emerald-500/50 focus:outline-none resize-none"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-gray-400 uppercase">Case Severity</label>
                    <select
                      value={severity}
                      onChange={(e) => setSeverity(e.target.value as any)}
                      className="w-full rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-2.5 text-sm text-white focus:border-emerald-500/50 focus:outline-none"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-gray-400 uppercase">Assign Investigator</label>
                    <select
                      value={assignedTo}
                      onChange={(e) => setAssignedTo(e.target.value)}
                      className="w-full rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-2.5 text-sm text-white focus:border-emerald-500/50 focus:outline-none"
                    >
                      <option value="">Leave Unassigned</option>
                      {usersData?.users.map((u) => (
                        <option key={u._id} value={u._id}>
                          {u.name} ({u.role})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Evidence Picker */}
                <div className="space-y-2">
                  <label className="text-xs font-semibold text-gray-400 uppercase block">Link Initial Evidence Assets</label>
                  <div className="rounded-lg border border-gray-800 bg-gray-900/30 max-h-40 overflow-y-auto divide-y divide-gray-900 p-2 space-y-1">
                    {contentData?.contents && contentData.contents.length === 0 ? (
                      <p className="text-xs text-gray-500 italic p-3 text-center">No registered content available to link.</p>
                    ) : (
                      contentData?.contents.map((item) => (
                        <div 
                          key={item._id} 
                          onClick={() => toggleEvidenceSelect(item._id)}
                          className={`flex items-center justify-between p-2 rounded-lg cursor-pointer transition-colors ${
                            selectedEvidence.includes(item._id) 
                              ? 'bg-emerald-500/10 border border-emerald-500/30' 
                              : 'hover:bg-gray-900/40 border border-transparent'
                          }`}
                        >
                          <div className="flex flex-col">
                            <span className="text-xs font-semibold text-white">{item.title}</span>
                            <span className="text-[10px] text-gray-500 capitalize">{item.contentType} • {item.status}</span>
                          </div>
                          <div className={`h-4 w-4 rounded border flex items-center justify-center ${
                            selectedEvidence.includes(item._id)
                              ? 'bg-emerald-400 border-emerald-400 text-gray-900'
                              : 'border-gray-700'
                          }`}>
                            {selectedEvidence.includes(item._id) && <span>✓</span>}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="flex justify-end gap-3 border-t border-gray-800 pt-3">
                  <button
                    type="button"
                    onClick={() => setCreateModalOpen(false)}
                    className="rounded-lg border border-gray-800 px-4 py-2 text-sm font-semibold text-gray-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={createMutation.isPending || title.trim().length < 3}
                    className="rounded-lg bg-emerald-400 px-4 py-2 text-sm font-semibold text-gray-900 hover:bg-emerald-300 disabled:opacity-50 flex items-center gap-1.5"
                  >
                    {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                    <span>Open Case</span>
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default CaseListPage;
