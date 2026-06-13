import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldCheck, User, Check, Flag, X, Search, 
  Shield, Loader2, Info, Activity, Database, Server, Clock, 
  Cpu, ArrowUpRight
} from 'lucide-react';
import apiClient from '../../lib/axios';
import type { Content, PaginatedResponse } from '../../types';

interface ExtendedContent extends Content {
  description?: string;
  merkleRoot?: string;
  chunkHashes?: string[];
  fileSize?: number;
  mimeType?: string;
  tags?: string[];
  isPublic: boolean;
  metadata?: Record<string, any>;
}

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return 'Unknown Size';
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / (3600 * 24));
  const h = Math.floor((seconds % (3600 * 24)) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);

  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(' ');
}

function AdminDashboardPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'queue' | 'metrics'>('queue');
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedItem, setSelectedItem] = useState<ExtendedContent | null>(null);
  
  // Flag modal states
  const [flaggingItem, setFlaggingItem] = useState<ExtendedContent | null>(null);
  const [flagReason, setFlagReason] = useState('');

  // Copy notification states
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Fetch pending content items
  const { data, isLoading, isError, refetch } = useQuery<PaginatedResponse<ExtendedContent>>({
    queryKey: ['admin-pending', page, searchQuery],
    queryFn: async () => {
      const params: Record<string, any> = { 
        status: 'pending', 
        page, 
        limit: 10 
      };
      if (searchQuery.trim().length > 0) {
        params.search = searchQuery.trim();
      }
      const res = await apiClient.get<PaginatedResponse<ExtendedContent>>('/content', { params });
      return res.data;
    },
    enabled: activeTab === 'queue'
  });

  // Fetch diagnostic health check
  const { data: healthData, isLoading: isHealthLoading } = useQuery<any>({
    queryKey: ['admin-health'],
    queryFn: async () => {
      const res = await apiClient.get('/health');
      return res.data;
    },
    refetchInterval: activeTab === 'metrics' ? 5000 : false,
    enabled: activeTab === 'metrics'
  });

  // Fetch live system performance metrics
  const { data: metricsData, isLoading: isMetricsLoading } = useQuery<any>({
    queryKey: ['admin-metrics'],
    queryFn: async () => {
      const res = await apiClient.get('/audit/metrics');
      return res.data;
    },
    refetchInterval: activeTab === 'metrics' ? 5000 : false,
    enabled: activeTab === 'metrics'
  });

  // Verify Mutation
  const verifyMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/content/${id}/verify`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-pending'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-total'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-verified'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-pending'] });
      if (selectedItem) setSelectedItem(null);
    }
  });

  // Flag Mutation
  const flagMutation = useMutation({
    mutationFn: async ({ id, reason }: { id: string; reason: string }) => {
      await apiClient.post(`/content/${id}/flag`, { reason });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-pending'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-total'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-verified'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-pending'] });
      setFlaggingItem(null);
      setFlagReason('');
      if (selectedItem) setSelectedItem(null);
    }
  });

  const triggerCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleVerify = (id: string) => {
    if (window.confirm('Are you sure you want to verify this content item?')) {
      verifyMutation.mutate(id);
    }
  };

  const handleOpenFlagModal = (e: React.MouseEvent, item: ExtendedContent) => {
    e.stopPropagation();
    setFlaggingItem(item);
  };

  const handleFlagSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!flaggingItem || !flagReason.trim()) return;
    flagMutation.mutate({ id: flaggingItem._id, reason: flagReason.trim() });
  };

  return (
    <section className="space-y-6">
      {/* Page Title */}
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
          <Shield className="h-8 w-8 text-cyan-400" />
          Audit Control Room
        </h1>
        <p className="text-gray-400">Review pending uploads, inspect cryptographic Merkle trees, and verify or flag digital evidence.</p>
      </div>

      {/* Tabs Selector */}
      <div className="flex border-b border-gray-800 gap-6 text-sm mb-6">
        <button
          onClick={() => setActiveTab('queue')}
          className={`pb-3 font-semibold transition relative outline-none ${
            activeTab === 'queue' ? 'text-cyan-400' : 'text-gray-400 hover:text-white'
          }`}
        >
          Audit Review Queue
          {activeTab === 'queue' && (
            <motion.div layoutId="activeTabBorder" className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400" />
          )}
        </button>
        <button
          onClick={() => setActiveTab('metrics')}
          className={`pb-3 font-semibold transition relative outline-none ${
            activeTab === 'metrics' ? 'text-cyan-400' : 'text-gray-400 hover:text-white'
          }`}
        >
          System Health & Metrics
          {activeTab === 'metrics' && (
            <motion.div layoutId="activeTabBorder" className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400" />
          )}
        </button>
      </div>

      <AnimatePresence mode="wait">
        {activeTab === 'queue' ? (
          <motion.div
            key="queue-view"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="grid gap-6 lg:grid-cols-3"
          >
            {/* Main List Table (Left 2 Columns) */}
            <div className="space-y-4 lg:col-span-2">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
                  <input
                    type="text"
                    placeholder="Search pending items by title, description or hash..."
                    value={searchQuery}
                    onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                    className="w-full rounded-lg border border-gray-800 bg-gray-900/40 py-2 pl-10 pr-4 text-sm text-white outline-none focus:border-cyan-500 placeholder-gray-600 transition"
                  />
                </div>
                <button
                  onClick={() => refetch()}
                  className="rounded-lg bg-gray-800 border border-gray-700 px-4 text-sm font-semibold text-white transition hover:bg-gray-700"
                >
                  Refresh
                </button>
              </div>

              <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900/20 backdrop-blur-sm">
                {isLoading ? (
                  <div className="flex flex-col items-center justify-center py-20 text-gray-400 space-y-4">
                    <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
                    <span>Loading pending registers...</span>
                  </div>
                ) : isError ? (
                  <div className="p-8 text-center text-red-400">
                    Failed to load audit logs. Verify administrative privileges.
                  </div>
                ) : !data || data.contents.length === 0 ? (
                  <div className="p-16 text-center text-gray-500 space-y-3">
                    <ShieldCheck className="h-12 w-12 mx-auto text-cyan-500/20" />
                    <p className="font-semibold text-white">All Clear!</p>
                    <p className="text-xs">No pending contents are awaiting forensic audit.</p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead>
                        <tr className="border-b border-gray-800 bg-gray-900/50 text-xs font-semibold uppercase tracking-wider text-gray-400">
                          <th className="px-5 py-4">Title / Type</th>
                          <th className="px-5 py-4">Owner</th>
                          <th className="px-5 py-4">Size</th>
                          <th className="px-5 py-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.contents.map((item) => (
                          <tr
                            key={item._id}
                            onClick={() => setSelectedItem(item)}
                            className={`border-b border-gray-800/60 cursor-pointer transition hover:bg-gray-900/40 ${
                              selectedItem?._id === item._id ? 'bg-gray-900/50' : ''
                            }`}
                          >
                            <td className="px-5 py-4">
                              <div className="font-semibold text-white">{item.title}</div>
                              <div className="text-xs text-gray-500 mt-1 capitalize">{item.contentType}</div>
                            </td>
                            <td className="px-5 py-4 text-gray-300">
                              <div className="flex items-center gap-1.5 text-xs">
                                <User className="h-3.5 w-3.5 text-gray-500" />
                                {item.owner?.name || 'Unknown'}
                              </div>
                            </td>
                            <td className="px-5 py-4 text-xs font-mono text-gray-400">
                              {formatBytes(item.fileSize)}
                            </td>
                            <td className="px-5 py-4 text-right" onClick={(e) => e.stopPropagation()}>
                              <div className="flex justify-end gap-1.5">
                                <button
                                  onClick={() => handleVerify(item._id)}
                                  disabled={verifyMutation.isPending || flagMutation.isPending}
                                  className="rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 p-1.5 transition"
                                  title="Verify/Approve Item"
                                >
                                  <Check className="h-4 w-4" />
                                </button>
                                <button
                                  onClick={(e) => handleOpenFlagModal(e, item)}
                                  disabled={verifyMutation.isPending || flagMutation.isPending}
                                  className="rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20 p-1.5 transition"
                                  title="Flag / Hold Item"
                                >
                                  <Flag className="h-4 w-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>

            {/* Side Panel: Drawer Detail Inspector (Right 1 Column) */}
            <div className="space-y-6">
              <div className="rounded-xl border border-gray-800 bg-gray-900/20 p-6 backdrop-blur-sm h-full min-h-[400px] flex flex-col justify-between shadow-lg">
                {selectedItem ? (
                  <div className="space-y-5 flex-1 flex flex-col justify-between">
                    <div className="space-y-5">
                      <div className="flex items-start justify-between border-b border-gray-800 pb-4">
                        <div>
                          <h2 className="font-bold text-white text-lg">{selectedItem.title}</h2>
                          <span className="text-xs text-gray-500 mt-1 capitalize block font-mono">
                            Type: {selectedItem.contentType} • {formatBytes(selectedItem.fileSize)}
                          </span>
                        </div>
                        <button
                          onClick={() => setSelectedItem(null)}
                          className="text-gray-500 hover:text-white"
                        >
                          <X className="h-5 w-5" />
                        </button>
                      </div>

                      <div className="space-y-4 text-xs">
                        <div className="space-y-1">
                          <span className="text-gray-500 block font-semibold">Description</span>
                          <p className="text-gray-300 bg-gray-950/40 p-3 rounded-lg border border-gray-900 leading-relaxed max-h-24 overflow-y-auto">
                            {selectedItem.description || 'No description provided.'}
                          </p>
                        </div>

                        <div className="space-y-1.5 font-mono">
                          <div className="flex items-center justify-between">
                            <span className="text-gray-500 font-semibold">Original Payload Hash</span>
                            <button
                              onClick={() => triggerCopy(selectedItem.originalHash, 'hash')}
                              className="text-cyan-400 hover:underline text-[10px]"
                            >
                              {copiedText === 'hash' ? 'Copied!' : 'Copy'}
                            </button>
                          </div>
                          <div className="rounded-lg bg-gray-950 p-2 text-[10px] break-all border border-gray-900 text-gray-400">
                            {selectedItem.originalHash}
                          </div>
                        </div>

                        <div className="space-y-1.5 font-mono">
                          <div className="flex items-center justify-between">
                            <span className="text-gray-500 font-semibold">Merkle Root Hash</span>
                            <button
                              onClick={() => triggerCopy(selectedItem.merkleRoot || '', 'root')}
                              className="text-cyan-400 hover:underline text-[10px]"
                            >
                              {copiedText === 'root' ? 'Copied!' : 'Copy'}
                            </button>
                          </div>
                          <div className="rounded-lg bg-gray-950 p-2 text-[10px] break-all border border-cyan-950 text-cyan-400">
                            {selectedItem.merkleRoot || 'N/A'}
                          </div>
                        </div>

                        {selectedItem.chunkHashes && selectedItem.chunkHashes.length > 0 && (
                          <div className="space-y-1 font-mono">
                            <span className="text-gray-500 font-semibold block">
                              Leaves ({selectedItem.chunkHashes.length} Chunks)
                            </span>
                            <div className="max-h-36 overflow-y-auto space-y-1.5 bg-gray-950/40 p-2 rounded-lg border border-gray-900 pr-1 select-text">
                              {selectedItem.chunkHashes.map((h, i) => (
                                <div key={i} className="flex gap-1.5 items-center text-[9px]">
                                  <span className="text-cyan-500 font-bold bg-cyan-500/5 px-1 rounded">{i}</span>
                                  <span className="truncate text-gray-500">{h}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="pt-4 border-t border-gray-800 flex gap-2 mt-4">
                      <button
                        onClick={() => handleVerify(selectedItem._id)}
                        disabled={verifyMutation.isPending || flagMutation.isPending}
                        className="flex-1 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold text-xs py-3 flex items-center justify-center gap-1.5 transition disabled:opacity-50"
                      >
                        <Check className="h-4 w-4" />
                        Verify
                      </button>
                      <button
                        onClick={(e) => handleOpenFlagModal(e, selectedItem)}
                        disabled={verifyMutation.isPending || flagMutation.isPending}
                        className="flex-1 rounded-lg border border-amber-500/30 hover:border-amber-500 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 font-bold text-xs py-3 flex items-center justify-center gap-1.5 transition disabled:opacity-50"
                      >
                        <Flag className="h-4 w-4" />
                        Flag Hold
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex-1 flex flex-col items-center justify-center text-center text-gray-500 py-10 space-y-3">
                    <Info className="h-10 w-10 text-gray-700" />
                    <div className="space-y-1">
                      <p className="font-semibold text-white">Inspector Panel</p>
                      <p className="text-xs max-w-[200px] text-gray-400">Select a pending item from the table to inspect cryptographic logs.</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        ) : (
          <motion.div
            key="metrics-view"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-6"
          >
            {/* Grid of Gauges & Service status */}
            <div className="grid gap-6 md:grid-cols-3">
              {/* Service Status Dashboard */}
              <div className="rounded-xl border border-gray-800 bg-gray-900/20 p-6 backdrop-blur-sm space-y-4 shadow-lg">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-gray-800 pb-2.5">
                  <Server className="h-4.5 w-4.5 text-cyan-400" />
                  Service Health status
                </h3>
                {isHealthLoading ? (
                  <div className="flex flex-col items-center justify-center py-10 text-gray-500 text-xs space-y-2">
                    <Loader2 className="h-5 w-5 text-cyan-400 animate-spin" />
                    <span>Resolving services state...</span>
                  </div>
                ) : (
                  <div className="space-y-3 font-mono text-xs">
                    <div className="flex items-center justify-between p-3 rounded-lg bg-gray-950/40 border border-gray-900">
                      <span className="text-gray-400">REST Gateway</span>
                      <div className="flex items-center gap-1.5 text-emerald-400">
                        <span className="h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_6px_#10b981] animate-pulse" />
                        <span className="font-semibold">ONLINE</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between p-3 rounded-lg bg-gray-950/40 border border-gray-900">
                      <span className="text-gray-400">Database Core</span>
                      <div className={`flex items-center gap-1.5 ${healthData?.services?.database?.status === 'connected' ? 'text-emerald-400' : 'text-rose-400'}`}>
                        <span className={`h-2 w-2 rounded-full bg-${healthData?.services?.database?.status === 'connected' ? 'emerald-500 shadow-[0_0_6px_#10b981]' : 'rose-500 shadow-[0_0_6px_#ef4444]'} animate-pulse`} />
                        <span className="font-semibold">{healthData?.services?.database?.status?.toUpperCase() || 'OFFLINE'}</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between p-3 rounded-lg bg-gray-950/40 border border-gray-900">
                      <span className="text-gray-400">Queue Broker</span>
                      <div className={`flex items-center gap-1.5 ${healthData?.services?.redis?.status === 'connected' ? 'text-emerald-400' : 'text-amber-500'}`}>
                        <span className={`h-2 w-2 rounded-full bg-${healthData?.services?.redis?.status === 'connected' ? 'emerald-500 shadow-[0_0_6px_#10b981]' : 'amber-500 shadow-[0_0_6px_#f59e0b]'} animate-pulse`} />
                        <span className="font-semibold">{healthData?.services?.redis?.status === 'connected' ? 'ONLINE' : 'FALLBACK'}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* System resource logs */}
              <div className="rounded-xl border border-gray-800 bg-gray-900/20 p-6 backdrop-blur-sm space-y-4 shadow-lg">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-gray-800 pb-2.5">
                  <Cpu className="h-4.5 w-4.5 text-cyan-400" />
                  Resource Telemetry
                </h3>
                {isHealthLoading ? (
                  <div className="flex flex-col items-center justify-center py-10 text-gray-500 text-xs space-y-2">
                    <Loader2 className="h-5 w-5 text-cyan-400 animate-spin" />
                    <span>Harvesting resource metrics...</span>
                  </div>
                ) : (
                  <div className="space-y-4 text-xs font-mono">
                    <div className="space-y-1.5">
                      <div className="flex justify-between text-gray-400">
                        <span>Heap Allocation</span>
                        <span className="text-white">
                          {healthData?.system?.memoryUsage ? `${Math.round(healthData.system.memoryUsage.heapUsed / 1024 / 1024)}MB / ${Math.round(healthData.system.memoryUsage.heapTotal / 1024 / 1024)}MB` : '0MB'}
                        </span>
                      </div>
                      <div className="h-2 w-full bg-gray-950 rounded-full overflow-hidden border border-gray-900">
                        <div 
                          className="h-full bg-cyan-400" 
                          style={{ 
                            width: healthData?.system?.memoryUsage 
                              ? `${(healthData.system.memoryUsage.heapUsed / healthData.system.memoryUsage.heapTotal) * 100}%` 
                              : '0%' 
                          }} 
                        />
                      </div>
                    </div>

                    <div className="flex items-center justify-between p-3 rounded-lg bg-gray-950/40 border border-gray-900">
                      <span className="text-gray-400 flex items-center gap-1.5">
                        <Clock className="h-4 w-4 text-gray-500" />
                        System Uptime
                      </span>
                      <span className="text-white font-semibold">
                        {healthData?.uptime ? formatUptime(healthData.uptime) : '0s'}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Traffic Summary metrics */}
              <div className="rounded-xl border border-gray-800 bg-gray-900/20 p-6 backdrop-blur-sm space-y-4 shadow-lg">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-gray-800 pb-2.5">
                  <Activity className="h-4.5 w-4.5 text-cyan-400" />
                  Traffic Telemetry
                </h3>
                {isMetricsLoading ? (
                  <div className="flex flex-col items-center justify-center py-10 text-gray-500 text-xs space-y-2">
                    <Loader2 className="h-5 w-5 text-cyan-400 animate-spin" />
                    <span>Resolving network logs...</span>
                  </div>
                ) : (
                  <div className="grid grid-cols-2 gap-3 text-center h-[90px] items-center">
                    <div className="rounded-lg bg-gray-950/40 border border-gray-900 p-3.5">
                      <span className="text-[9px] font-mono text-gray-500 block uppercase tracking-wider">NETWORK HITS</span>
                      <span className="text-xl font-bold text-white font-mono mt-1 block">
                        {metricsData?.trafficStats?.totalRequests || 0}
                      </span>
                    </div>
                    <div className="rounded-lg bg-gray-950/40 border border-gray-900 p-3.5">
                      <span className="text-[9px] font-mono text-gray-500 block uppercase tracking-wider">AVG LATENCY</span>
                      <span className="text-xl font-bold text-emerald-400 font-mono mt-1 block">
                        {metricsData?.trafficStats?.avgResponseTimeMs || 0} ms
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Inventory Ledger metrics */}
            <div className="rounded-xl border border-gray-800 bg-gray-900/20 p-6 backdrop-blur-sm space-y-4 shadow-lg">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-gray-800 pb-2.5">
                <Database className="h-4.5 w-4.5 text-cyan-400" />
                Ledger Spec Count
              </h3>
              {isMetricsLoading ? (
                <div className="flex justify-center py-6 text-gray-500 text-xs">Loading ledger summaries...</div>
              ) : (
                <div className="grid gap-4 grid-cols-2 sm:grid-cols-4 font-mono text-xs">
                  <div className="p-4 rounded-xl bg-gray-950/40 border border-gray-900 text-center">
                    <span className="text-gray-500 block uppercase text-[10px] tracking-wider">TOTAL CONTENT</span>
                    <span className="text-2xl font-bold text-white mt-1.5 block">{metricsData?.dbStats?.totalContents || 0}</span>
                  </div>
                  <div className="p-4 rounded-xl bg-gray-950/40 border border-gray-900 text-center">
                    <span className="text-gray-500 block uppercase text-[10px] tracking-wider">CUSTODY EVENTS</span>
                    <span className="text-2xl font-bold text-white mt-1.5 block">{metricsData?.dbStats?.totalAuditLogs || 0}</span>
                  </div>
                  <div className="p-4 rounded-xl bg-gray-950/40 border border-gray-900 text-center">
                    <span className="text-gray-500 block uppercase text-[10px] tracking-wider">forensic CASES</span>
                    <span className="text-2xl font-bold text-white mt-1.5 block">{metricsData?.dbStats?.totalCases || 0}</span>
                  </div>
                  <div className="p-4 rounded-xl bg-gray-950/40 border border-gray-900 text-center">
                    <span className="text-gray-500 block uppercase text-[10px] tracking-wider">INVESTIGATORS</span>
                    <span className="text-2xl font-bold text-white mt-1.5 block">{metricsData?.dbStats?.totalUsers || 0}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Traffic Performance logs */}
            <div className="rounded-xl border border-gray-800 bg-gray-900/20 backdrop-blur-sm overflow-hidden shadow-lg space-y-3">
              <div className="p-5 border-b border-gray-800">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ArrowUpRight className="h-4.5 w-4.5 text-cyan-400" />
                  Route Latency Telemetry
                </h3>
              </div>
              {isMetricsLoading ? (
                <div className="flex justify-center py-10 text-gray-500 text-xs">Loading route metrics...</div>
              ) : !metricsData?.trafficStats?.routeBreakdown || metricsData.trafficStats.routeBreakdown.length === 0 ? (
                <div className="py-10 text-center text-gray-500 text-xs font-mono">NO NETWORK FLOW RECORDED IN LEDGER.</div>
              ) : (
                <div className="overflow-x-auto text-xs font-mono">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-gray-800 bg-gray-950/50 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                        <th className="px-5 py-3.5">Endpoint Pattern</th>
                        <th className="px-5 py-3.5 text-center">Count</th>
                        <th className="px-5 py-3.5 text-right">Average Latency</th>
                        <th className="px-5 py-3.5 text-right font-bold">Peak Response</th>
                      </tr>
                    </thead>
                    <tbody>
                      {metricsData.trafficStats.routeBreakdown.map((routeObj: any, idx: number) => (
                        <tr key={idx} className="border-b border-gray-850 hover:bg-gray-900/25">
                          <td className="px-5 py-3.5 text-gray-300 font-semibold">{routeObj.route}</td>
                          <td className="px-5 py-3.5 text-center text-white">{routeObj.count}</td>
                          <td className="px-5 py-3.5 text-right text-emerald-400">{routeObj.avgResponseTimeMs} ms</td>
                          <td className="px-5 py-3.5 text-right text-amber-500 font-bold">{routeObj.maxResponseTimeMs} ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Flag Reason Modal Dialog */}
      <AnimatePresence>
        {flaggingItem && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md rounded-2xl border border-gray-800 bg-gray-905 p-6 shadow-2xl space-y-4 bg-gray-900"
            >
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-bold text-white">Flag Content</h3>
                  <p className="text-xs text-gray-400 mt-0.5">Specify why {flaggingItem.title} is being flagged.</p>
                </div>
                <button
                  onClick={() => { setFlaggingItem(null); setFlagReason(''); }}
                  className="text-gray-500 hover:text-white"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <form onSubmit={handleFlagSubmit} className="space-y-4">
                <div>
                  <label htmlFor="flag-reason" className="mb-1 block text-xs font-semibold text-gray-300">Flagging Reason</label>
                  <textarea
                    id="flag-reason"
                    rows={4}
                    required
                    placeholder="e.g. Suspected metadata alteration, compression frame mismatch, etc."
                    value={flagReason}
                    onChange={(e) => setFlagReason(e.target.value)}
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-white outline-none focus:border-amber-500 ring-amber-500/40 focus:ring resize-none placeholder-gray-600"
                  />
                </div>

                <div className="flex justify-end gap-2 text-xs">
                  <button
                    type="button"
                    onClick={() => { setFlaggingItem(null); setFlagReason(''); }}
                    className="rounded-lg border border-gray-800 px-4 py-2 font-semibold text-white hover:bg-gray-800 transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={flagMutation.isPending}
                    className="rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-950 font-bold px-4 py-2 flex items-center gap-1 transition disabled:opacity-50"
                  >
                    {flagMutation.isPending ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Flagging...
                      </>
                    ) : (
                      <>
                        <Flag className="h-4.5 w-4.5" />
                        Flag Evidence
                      </>
                    )}
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </section>
  );
}

export default AdminDashboardPage;
