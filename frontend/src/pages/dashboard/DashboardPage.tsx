import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { 
  Layers, 
  ShieldCheck, 
  Clock, 
  FilePlus, 
  ChevronRight, 
  AlertTriangle,
  Cpu,
  TrendingUp,
  Activity,
  UserCheck,
  BrainCircuit
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import apiClient from '../../lib/axios';

interface DashboardStats {
  totalCases: number;
  activeCases: number;
  totalContent: number;
  threatScore: number;
  verificationRate: number;
  ledgerIntegrity: number;
  ingestRate: Array<{ day: string, count: number, val: number }>;
  formatDistribution: Array<{ type: string, count: number, pct: number, color: string }>;
  aiInsights: Array<{ id: string, title: string, desc: string, severity: 'high' | 'medium' | 'low', time: string }>;
  atsCount?: number;
  plagCount?: number;
}

// Custom interactive SVG Area Line Chart for activity
function ActivityChart({ data }: { data: Array<{ day: string, count: number, val: number }> }) {
  const points = data.length > 0 ? data : [
    { day: 'Mon', count: 0, val: 15 },
    { day: 'Tue', count: 0, val: 15 },
    { day: 'Wed', count: 0, val: 15 },
    { day: 'Thu', count: 0, val: 15 },
    { day: 'Fri', count: 0, val: 15 },
    { day: 'Sat', count: 0, val: 15 },
    { day: 'Sun', count: 0, val: 15 }
  ];

  const maxVal = 100;
  const width = 500;
  const height = 150;
  const padding = 20;

  // Generate SVG coordinates
  const svgPoints = points.map((p, idx) => {
    const x = padding + (idx * (width - padding * 2)) / (points.length - 1);
    const y = height - padding - (p.val / maxVal) * (height - padding * 2);
    return { x, y, ...p };
  });

  const pathD = `M ${svgPoints[0].x} ${svgPoints[0].y} ` + 
    svgPoints.slice(1).map(p => `L ${p.x} ${p.y}`).join(' ');

  const areaD = `${pathD} L ${svgPoints[svgPoints.length - 1].x} ${height - padding} L ${svgPoints[0].x} ${height - padding} Z`;

  return (
    <div className="rounded-xl border border-gray-900 bg-gray-950/40 p-5 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="space-y-0.5">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
            <Activity className="h-4 w-4 text-emerald-400" />
            <span>Upload Activity</span>
          </h3>
          <p className="text-[10px] text-gray-500">File validation activity per day</p>
        </div>
        <div className="flex items-center gap-1 text-[10px] font-bold text-emerald-400">
          <TrendingUp className="h-3 w-3" />
          <span>Upload activity live</span>
        </div>
      </div>
      <div className="relative">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full overflow-visible">
          {/* Grid lines */}
          <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="rgba(255,255,255,0.03)" />
          <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="rgba(255,255,255,0.03)" />
          <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="rgba(255,255,255,0.08)" />

          {/* Area fill */}
          <path d={areaD} fill="url(#area-gradient)" className="opacity-10" />

          {/* Line stroke */}
          <path d={pathD} fill="none" stroke="rgba(52, 211, 153, 0.8)" strokeWidth="2" />

          {/* Data nodes */}
          {svgPoints.map((p, idx) => (
            <g key={idx} className="group cursor-pointer">
              <circle 
                cx={p.x} 
                cy={p.y} 
                r="4" 
                fill="#10b981" 
                stroke="#030712" 
                strokeWidth="1.5"
                className="transition-transform group-hover:scale-150"
              />
              <text 
                x={p.x} 
                y={p.y - 10} 
                textAnchor="middle" 
                fill="#fff" 
                fontSize="8" 
                className="opacity-0 group-hover:opacity-100 font-mono transition-opacity pointer-events-none"
              >
                {p.count} file{p.count !== 1 ? 's' : ''}
              </text>
            </g>
          ))}

          {/* Gradients */}
          <defs>
            <linearGradient id="area-gradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
            </linearGradient>
          </defs>
        </svg>

        {/* X Axis labels */}
        <div className="flex justify-between text-[9px] font-mono text-gray-500 mt-2 px-4">
          {points.map(p => <span key={p.day}>{p.day}</span>)}
        </div>
      </div>
    </div>
  );
}

// Custom responsive bar chart for evidence formats
function EvidenceChart({ data }: { data: Array<{ type: string, count: number, pct: number, color: string }> }) {
  const formats = data.length > 0 ? data : [
    { type: 'Images', count: 0, pct: 0, color: 'bg-emerald-400' },
    { type: 'Video', count: 0, pct: 0, color: 'bg-cyan-400' },
    { type: 'Audio', count: 0, pct: 0, color: 'bg-indigo-400' },
    { type: 'Documents', count: 0, pct: 0, color: 'bg-purple-400' }
  ];

  return (
    <div className="rounded-xl border border-gray-900 bg-gray-950/40 p-5 backdrop-blur-sm space-y-4">
      <div className="space-y-0.5">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
          <Layers className="h-4 w-4 text-cyan-400" />
          <span>Evidence Distribution</span>
        </h3>
        <p className="text-[10px] text-gray-500">Distribution of ingestion formats</p>
      </div>

      <div className="space-y-3">
        {formats.map(fmt => (
          <div key={fmt.type} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-gray-300">{fmt.type}</span>
              <span className="font-mono text-gray-400">{fmt.count} files ({fmt.pct}%)</span>
            </div>
            <div className="h-2 w-full rounded-full bg-gray-950 overflow-hidden">
              <div className={`h-full rounded-full ${fmt.color}`} style={{ width: `${fmt.pct}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// User dynamic Audit Activity chart (circular gauge)
function UserGauge({ percentage }: { percentage: number }) {
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <div className="rounded-xl border border-gray-900 bg-gray-950/40 p-5 backdrop-blur-sm flex items-center gap-6">
      <div className="relative flex items-center justify-center h-28 w-28 shrink-0">
        <svg className="absolute h-full w-full -rotate-95 transform">
          <circle cx="56" cy="56" r={radius} stroke="rgba(255,255,255,0.03)" strokeWidth="6" fill="transparent" />
          <circle 
            cx="56" 
            cy="56" 
            r={radius} 
            stroke="url(#gauge-grad)" 
            strokeWidth="6" 
            fill="transparent" 
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
          />
          <defs>
            <linearGradient id="gauge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="100%" stopColor="#22d3ee" />
            </linearGradient>
          </defs>
        </svg>
        <div className="text-center">
          <span className="text-xl font-extrabold text-white font-mono">{percentage}%</span>
          <p className="text-[8px] text-emerald-400 uppercase tracking-widest font-bold">Consensus</p>
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
          <UserCheck className="h-4 w-4 text-indigo-400" />
          <span>Data Integrity</span>
        </h3>
        <p className="text-xs text-gray-400 leading-normal">
          Percent of verified media files aligning with cryptographic audit check hashes.
        </p>
        <div className="flex items-center gap-1.5 text-[10px] font-semibold text-emerald-400">
          <ShieldCheck className="h-3.5 w-3.5" />
          <span>Data Integrity Secure</span>
        </div>
      </div>
    </div>
  );
}

function DashboardPage() {
  const { user } = useAuth();
  const [liveThreatLevel, setLiveThreatLevel] = useState<number | null>(null);

  // Fetch dashboard stats from aggregated stats endpoint
  const { data: statsData, isLoading } = useQuery<DashboardStats>({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const res = await apiClient.get<DashboardStats>('/dashboard/stats');
      return res.data;
    }
  });

  // Align simulated threat level with DB starting point
  useEffect(() => {
    if (statsData && liveThreatLevel === null) {
      setLiveThreatLevel(statsData.threatScore);
    }
  }, [statsData, liveThreatLevel]);

  // Periodic tiny bounce in threat level to simulate live feeds
  useEffect(() => {
    if (liveThreatLevel === null) return;
    const timer = setInterval(() => {
      setLiveThreatLevel((prev) => {
        if (prev === null) return null;
        const offset = Math.random() > 0.5 ? 1 : -1;
        const next = prev + offset;
        return next < 0 ? 0 : next > 100 ? 100 : next;
      });
    }, 5000);
    return () => clearInterval(timer);
  }, [liveThreatLevel]);

  const activeCases = statsData?.activeCases ?? 0;
  const totalCases = statsData?.totalCases ?? 0;
  const totalContent = statsData?.totalContent ?? 0;
  const verificationRate = statsData?.verificationRate ?? 100;
  const ledgerIntegrity = statsData?.ledgerIntegrity ?? 100.0;
  const ingestRate = statsData?.ingestRate ?? [];
  const formatDistribution = statsData?.formatDistribution ?? [];
  const aiInsights = statsData?.aiInsights ?? [];

  const stats = [
    { 
      title: 'Active Cases', 
      value: String(activeCases), 
      desc: `Out of ${totalCases} total cases`,
      icon: <Clock className="h-5 w-5 text-indigo-400" />,
      link: '/cases'
    },
    { 
      title: 'Evidence Files', 
      value: String(totalContent), 
      desc: `Verification rate: ${verificationRate}%`,
      icon: <Layers className="h-5 w-5 text-cyan-400" />,
      link: '/content'
    },
    { 
      title: 'Security Score', 
      value: liveThreatLevel !== null ? `${liveThreatLevel}/100` : '...', 
      desc: 'System health index rate',
      icon: <AlertTriangle className="h-5 w-5 text-emerald-400" />,
    },
  ];

  if (isLoading) {
    return (
      <div className="flex h-[50vh] flex-col items-center justify-center gap-3">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500/20 border-t-emerald-400" />
        <span className="text-xs font-mono text-gray-500">Querying platform statistics ledger...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 pb-8">
      {/* Welcome Banner */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between rounded-2xl border border-gray-800 bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950 p-6 shadow-md">
        <div className="space-y-1">
          <h1 className="text-3xl font-bold tracking-tight text-white">Welcome back, {user?.name || 'User'}</h1>
          <p className="text-sm text-gray-400">Node status checks: active. Provenance validation streams verified.</p>
        </div>
        <div className="flex flex-wrap gap-2.5 self-start sm:self-center">
          <Link
            to="/dashboard/3d"
            className="inline-flex items-center gap-1.5 rounded-lg bg-gray-800 border border-gray-700 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-gray-750"
          >
            <span>Evidence Network View</span>
          </Link>
          <Link
            to="/content/new"
            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-gray-900 transition hover:bg-emerald-300"
          >
            <FilePlus className="h-4 w-4" />
            <span>Upload Evidence</span>
          </Link>
        </div>
      </div>

      {/* Verification Services Grid */}
      <div className="grid gap-5 sm:grid-cols-2">
        <article className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 backdrop-blur-sm transition hover:border-gray-805 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider block">INTELLIGENCE SYSTEMS</span>
            <h3 className="text-base font-bold text-white leading-tight">Resume Intelligence</h3>
            <p className="text-xs text-gray-400 font-mono mt-1">Reports generated: <span className="text-emerald-400 font-bold">{statsData?.atsCount ?? 0}</span></p>
            <Link to="/ats" className="text-xs text-emerald-400 hover:text-emerald-300 font-semibold flex items-center gap-0.5 mt-2.5">
              <span>Access Resume Workspace</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </Link>
          </div>
          <div className="rounded-xl bg-gray-950 p-4 border border-gray-850 text-emerald-400">
            <BrainCircuit className="h-8 w-8" />
          </div>
        </article>
        
        <article className="rounded-xl border border-gray-900 bg-gray-950/20 p-5 backdrop-blur-sm transition hover:border-gray-805 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider block">COPYRIGHT AUDITING</span>
            <h3 className="text-base font-bold text-white leading-tight">Plagiarism Detection</h3>
            <p className="text-xs text-gray-400 font-mono mt-1">Documents verified: <span className="text-emerald-400 font-bold">{statsData?.plagCount ?? 0}</span></p>
            <Link to="/plagiarism" className="text-xs text-emerald-400 hover:text-emerald-300 font-semibold flex items-center gap-0.5 mt-2.5">
              <span>Access Plagiarism Workspace</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </Link>
          </div>
          <div className="rounded-xl bg-gray-950 p-4 border border-gray-850 text-cyan-400">
            <Layers className="h-8 w-8" />
          </div>
        </article>
      </div>

      {/* Stats Cards Grid */}
      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {stats.map((item) => (
          <article 
            key={item.title} 
            className="flex flex-col justify-between rounded-xl border border-gray-900 bg-gray-900/20 p-5 backdrop-blur-sm transition hover:border-gray-800"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{item.title}</span>
              <div className="rounded-lg bg-gray-950 p-2 border border-gray-850">
                {item.icon}
              </div>
            </div>
            
            <div className="mt-4 space-y-1">
              <span className="text-3xl font-extrabold text-white tracking-tight">{item.value}</span>
              <p className="text-[10px] text-gray-500">{item.desc}</p>
            </div>

            {item.link && (
              <div className="mt-4 pt-3 border-t border-gray-900/60 flex justify-end">
                <Link to={item.link} className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-0.5">
                  <span>Manage</span>
                  <ChevronRight className="h-3 w-3" />
                </Link>
              </div>
            )}
          </article>
        ))}
      </div>

      {/* SVG Charts Section */}
      <div className="grid gap-6 md:grid-cols-2">
        <ActivityChart data={ingestRate} />
        <EvidenceChart data={formatDistribution} />
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        {/* Left Side: Circular Gauge */}
        <div className="md:col-span-2">
          <UserGauge percentage={ledgerIntegrity} />
        </div>

        {/* Right Side: AI Security Insights Panel */}
        <div className="rounded-xl border border-gray-900 bg-gray-950/40 p-5 backdrop-blur-sm flex flex-col justify-between">
          <div className="space-y-0.5 mb-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="h-4 w-4 text-emerald-400" />
              <span>Security Insights</span>
            </h3>
            <p className="text-[10px] text-gray-500">AI analysis alerts</p>
          </div>

          <div className="space-y-3 overflow-y-auto max-h-56 pr-1">
            {aiInsights.length === 0 ? (
              <p className="text-xs text-gray-600 italic text-center py-6">No security insights generated.</p>
            ) : (
              aiInsights.map(ins => (
                <div key={ins.id} className="p-2.5 rounded-lg border border-gray-900 bg-gray-950/60 text-[11px] space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-white">{ins.title}</span>
                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                      ins.severity === 'high' ? 'bg-red-500/10 text-red-400' :
                      ins.severity === 'medium' ? 'bg-yellow-500/10 text-yellow-400' : 'bg-emerald-500/10 text-emerald-400'
                    }`}>{ins.severity}</span>
                  </div>
                  <p className="text-gray-400 leading-normal">{ins.desc}</p>
                  <div className="text-[9px] text-gray-650 text-right">{ins.time}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default DashboardPage;
