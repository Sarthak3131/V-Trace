import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, CheckCircle2, AlertTriangle, Loader2,
  Lock, RefreshCw, Search, Database, User, Calendar
} from 'lucide-react';
import apiClient from '../../lib/axios';
import { useAuthStore } from '../../store/authStore';

interface AuditRecord {
  _id: string;
  action: string;
  entityType: 'Content' | 'Case' | 'User';
  entityId: string;
  performedBy: {
    _id: string;
    name: string;
    email: string;
    role: string;
  };
  details?: Record<string, any>;
  timestamp: string;
  previousLogHash: string;
  hash: string;
}

interface AuditVerifyResult {
  verified: boolean;
  compromisedLogsCount: number;
  compromisedLogs: Array<{
    _id: string;
    action: string;
    entityType: string;
    entityId: string;
    timestamp: string;
    expectedHash: string;
    actualHash: string;
    expectedPrevHash: string;
    actualPrevHash: string;
  }>;
}

function getActionLabel(action: string) {
  return action
    .replace('-', ' ')
    .replace('-', ' ')
    .toUpperCase();
}

function getActionColor(action: string) {
  if (action.includes('created') || action.includes('register')) {
    return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  }
  if (action.includes('verified')) {
    return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  }
  if (action.includes('flagged') || action.includes('updated')) {
    return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
  }
  if (action.includes('deleted') || action.includes('compromised') || action.includes('rejected')) {
    return 'bg-red-500/10 text-red-400 border-red-500/20';
  }
  return 'bg-gray-800 text-gray-400 border-gray-700';
}

function AuditLogPage() {
  const currentUser = useAuthStore((state) => state.user);
  const isPrivileged = currentUser?.role === 'admin' || currentUser?.role === 'moderator';

  // Filters state
  const [actionFilter, setActionFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [searchEntity, setSearchEntity] = useState('');
  const [page, setPage] = useState(1);

  // Fetch paginated audit logs
  const { data: auditData, isLoading, isError, refetch } = useQuery<{
    logs: AuditRecord[];
    pagination: { page: number; limit: number; total: number; pages: number };
  }>({
    queryKey: ['audit-logs-list', actionFilter, typeFilter, searchEntity, page],
    queryFn: async () => {
      const params: Record<string, string> = { page: String(page), limit: '15' };
      if (actionFilter) params.action = actionFilter;
      if (typeFilter) params.entityType = typeFilter;
      if (searchEntity.trim()) params.entityId = searchEntity.trim();

      const res = await apiClient.get('/audit', { params });
      return res.data;
    }
  });

  // Verify cryptographic chain integrity mutation
  const verifyMutation = useMutation<AuditVerifyResult>({
    mutationFn: async () => {
      const res = await apiClient.get('/audit/verify');
      return res.data;
    }
  });

  const handleVerifyClick = () => {
    verifyMutation.mutate();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-gray-800 pb-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
            <Lock className="h-7 w-7 text-emerald-400" />
            <span>Activity History Logs</span>
          </h1>
          <p className="text-gray-400">
            Track system operations and verify the integrity of the evidence registry.
          </p>
        </div>

        {isPrivileged && (
          <button
            onClick={handleVerifyClick}
            disabled={verifyMutation.isPending}
            className="rounded-lg bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-gray-900 transition hover:bg-emerald-300 flex items-center gap-1.5 disabled:opacity-50 self-start sm:self-center"
          >
            {verifyMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            <span>Verify Log Integrity</span>
          </button>
        )}
      </div>

      {/* Chain Verification Result Banner */}
      <AnimatePresence>
        {verifyMutation.data && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className={`rounded-xl border p-5 ${
              verifyMutation.data.verified
                ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-400'
                : 'bg-red-950/20 border-red-500/30 text-red-400'
            }`}
          >
            <div className="flex items-start gap-3">
              {verifyMutation.data.verified ? (
                <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0" />
              ) : (
                <ShieldAlert className="h-6 w-6 text-red-400 shrink-0" />
              )}
              <div className="space-y-2 flex-1">
                <h3 className="text-base font-bold">
                  {verifyMutation.data.verified
                    ? 'Log Verification Passed'
                    : `Log Integrity Issue Detected (${verifyMutation.data.compromisedLogsCount} flag(s))`
                  }
                </h3>
                <p className="text-sm text-gray-300 leading-relaxed">
                  {verifyMutation.data.verified
                    ? 'All logs match expected signatures. The activity history logs are validated as complete and unmodified.'
                    : 'The log hashes do not match. Evidence records or history entries may have been modified outside the standard platform APIs.'
                  }
                </p>
                
                {!verifyMutation.data.verified && verifyMutation.data.compromisedLogs.length > 0 && (
                  <div className="mt-4 rounded-lg bg-gray-950/80 border border-red-500/20 p-3 space-y-2">
                    <p className="text-xs font-bold text-red-400 flex items-center gap-1.5">
                      <AlertTriangle className="h-4 w-4" />
                      <span>INTEGRITY ISSUES DETECTED:</span>
                    </p>
                    <div className="divide-y divide-gray-900 max-h-40 overflow-y-auto font-mono text-[10px] text-gray-400">
                      {verifyMutation.data.compromisedLogs.map((log) => (
                        <div key={log._id} className="py-2 space-y-1">
                          <div className="flex justify-between">
                            <span className="text-red-400 font-bold">Log ID: {log._id}</span>
                            <span>{log.action} ({log.entityType})</span>
                          </div>
                          <div>Expected Prev Hash: <span className="text-emerald-400">{log.expectedPrevHash.substring(0, 16)}...</span></div>
                          <div>Actual Prev Hash: <span className="text-red-400">{log.actualPrevHash.substring(0, 16)}...</span></div>
                          <div>Expected Self Hash: <span className="text-emerald-400">{log.expectedHash.substring(0, 16)}...</span></div>
                          <div>Actual Self Hash: <span className="text-red-400">{log.actualHash.substring(0, 16)}...</span></div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-gray-800 bg-gray-900/30 p-4">
        <div className="flex items-center gap-1.5 text-sm text-gray-400 pr-2 border-r border-gray-800">
          <Search className="h-4 w-4 text-gray-500" />
          <span>Filters:</span>
        </div>

        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 focus:border-emerald-500/50 focus:outline-none"
        >
          <option value="">All Actions</option>
          <option value="content-registered">Content Registered</option>
          <option value="content-verified">Content Verified</option>
          <option value="content-flagged">Content Flagged</option>
          <option value="content-deleted">Content Deleted</option>
          <option value="case-created">Case Created</option>
          <option value="case-status-changed">Case Status Changed</option>
          <option value="case-severity-changed">Case Severity Changed</option>
          <option value="case-assigned">Case Assigned</option>
          <option value="case-unassigned">Case Unassigned</option>
          <option value="case-note-added">Case Note Logged</option>
          <option value="case-evidence-linked">Evidence Linked</option>
          <option value="case-evidence-unlinked">Evidence Unlinked</option>
          <option value="user-registered">User Registered</option>
        </select>

        <select
          value={typeFilter}
          onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 focus:border-emerald-500/50 focus:outline-none"
        >
          <option value="">All Entity Types</option>
          <option value="Content">Content (Evidence)</option>
          <option value="Case">Case</option>
          <option value="User">User</option>
        </select>

        <input
          type="text"
          value={searchEntity}
          onChange={(e) => { setSearchEntity(e.target.value); setPage(1); }}
          placeholder="Filter by Entity ID..."
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 placeholder-gray-600 focus:border-emerald-500/50 focus:outline-none w-48 font-mono"
        />

        <button
          onClick={() => refetch()}
          className="ml-auto rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 px-3 py-1.5 text-xs text-white"
        >
          Refresh Feed
        </button>
      </div>

      {/* Main Audit Feed */}
      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <Loader2 className="h-10 w-10 text-emerald-400 animate-spin" />
          <p className="text-gray-400 text-sm">Loading activity logs...</p>
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center text-red-400">
          Failed to fetch audit records. Try refreshing the page.
        </div>
      ) : auditData && auditData.logs.length === 0 ? (
        <div className="rounded-xl border border-dashed border-gray-800 bg-gray-900/10 p-12 text-center text-gray-500 flex flex-col items-center gap-3">
          <Database className="h-10 w-10 text-gray-700" />
          <p className="text-sm">No activity history events found matching your query filters.</p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-950">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-400">
                <thead className="bg-gray-900/50 text-xs uppercase text-gray-300 border-b border-gray-800">
                  <tr>
                    <th className="px-6 py-4">Log ID</th>
                    <th className="px-6 py-4">Action</th>
                    <th className="px-6 py-4">Entity reference</th>
                    <th className="px-6 py-4">Performed By</th>
                    <th className="px-6 py-4">Logged Date</th>
                    <th className="px-6 py-4">Verification Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-900">
                  {auditData?.logs.map((log) => (
                    <tr key={log._id} className="hover:bg-gray-900/20 transition-colors text-xs">
                      <td className="px-6 py-4 font-mono text-emerald-400 font-semibold select-all">
                        {log._id}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex rounded border px-2 py-0.5 text-[9px] font-semibold tracking-wider ${getActionColor(log.action)}`}>
                          {getActionLabel(log.action)}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap space-y-0.5">
                        <div className="font-semibold text-gray-300">{log.entityType}</div>
                        <div className="font-mono text-[10px] text-gray-500 select-all">{log.entityId}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <User className="h-3 w-3 text-emerald-400" />
                          <div>
                            <span className="block font-medium text-gray-300">{log.performedBy?.name || 'System'}</span>
                            <span className="block text-[10px] text-gray-500 capitalize">{log.performedBy?.role || 'Service'}</span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap space-y-0.5 text-gray-500">
                        <div className="flex items-center gap-1">
                          <Calendar className="h-3 w-3" />
                          <span>{new Date(log.timestamp).toLocaleDateString()}</span>
                        </div>
                        <div className="text-[10px] pl-4">{new Date(log.timestamp).toLocaleTimeString()}</div>
                      </td>
                      <td className="px-6 py-4 font-mono text-[9px] text-gray-600 select-all max-w-[120px] truncate" title={log.hash}>
                        {log.hash.substring(0, 16)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination Controls */}
          {auditData && auditData.pagination.pages > 1 && (
            <div className="flex justify-between items-center bg-gray-950/20 p-3 rounded-lg border border-gray-900 text-xs">
              <span className="text-gray-500">
                Showing page {auditData.pagination.page} of {auditData.pagination.pages} ({auditData.pagination.total} total events)
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(p => Math.max(p - 1, 1))}
                  disabled={page === 1}
                  className="rounded border border-gray-800 bg-gray-950 px-3 py-1 text-white hover:bg-gray-900 disabled:opacity-30"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage(p => Math.min(p + 1, auditData.pagination.pages))}
                  disabled={page === auditData.pagination.pages}
                  className="rounded border border-gray-800 bg-gray-950 px-3 py-1 text-white hover:bg-gray-900 disabled:opacity-30"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default AuditLogPage;
