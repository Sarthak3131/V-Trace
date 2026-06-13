import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { 
  Film, Image, Music, FileText, File, 
  ArrowDown, CheckCircle2, AlertTriangle, XCircle, Clock
} from 'lucide-react';

export interface GraphNode {
  id: string;
  title: string;
  contentType: string;
  originalHash: string;
  status: string;
  owner: string;
  derivationType: string;
  scores: {
    authenticity: number;
    provenance: number;
    aiManipulation: number;
    trust: number;
    confidence?: number;
  };
  activeCases?: Array<{
    _id: string;
    title: string;
    status: string;
    severity: string;
  }>;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
  weight?: number;
}

interface ProvenanceGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  targetId: string;
}

function getFileTypeIcon(type: string) {
  switch (type) {
    case 'video': return <Film className="h-3.5 w-3.5" />;
    case 'image': return <Image className="h-3.5 w-3.5" />;
    case 'audio': return <Music className="h-3.5 w-3.5" />;
    case 'text': return <FileText className="h-3.5 w-3.5" />;
    default: return <File className="h-3.5 w-3.5" />;
  }
}

function getDerivationBadge(type: string) {
  switch (type) {
    case 'original':
      return <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded text-[10px] font-semibold uppercase">Original</span>;
    case 'copy':
      return <span className="bg-gray-800 text-gray-400 border border-gray-750 px-2 py-0.5 rounded text-[10px] font-semibold uppercase">Copy</span>;
    case 'edit':
      return <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded text-[10px] font-semibold uppercase">Edit</span>;
    case 'ai-modification':
      return <span className="bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded text-[10px] font-semibold uppercase">AI Modified</span>;
    case 'splice':
      return <span className="bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded text-[10px] font-semibold uppercase">Splice</span>;
    default:
      return <span className="bg-gray-800 text-gray-400 border border-gray-750 px-2 py-0.5 rounded text-[10px] font-semibold uppercase">Derived</span>;
  }
}

function getTrustScoreColor(score: number) {
  if (score >= 80) return 'text-emerald-400 border-emerald-500/30';
  if (score >= 50) return 'text-amber-400 border-amber-500/30';
  return 'text-red-400 border-red-500/30';
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'verified': return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case 'flagged': return <AlertTriangle className="h-4 w-4 text-amber-400" />;
    case 'rejected': return <XCircle className="h-4 w-4 text-red-400" />;
    default: return <Clock className="h-4 w-4 text-gray-500" />;
  }
}

export function ProvenanceGraph({ nodes, links, targetId }: ProvenanceGraphProps) {
  // Sort nodes to render lineage vertically:
  // 1. Trace parent chain of targetNode to organize ancestors.
  // 2. Put targetNode.
  // 3. Put children nodes.
  
  const targetNode = nodes.find(n => n.id === targetId);
  if (!targetNode) return null;

  // Resolve ancestors
  const ancestors: GraphNode[] = [];
  let currentParentId = nodes.find(n => n.id === targetId)?.id;
  const visited = new Set<string>();

  while (currentParentId) {
    const parentLink = links.find(l => l.target === currentParentId);
    if (parentLink && parentLink.source !== currentParentId && !visited.has(parentLink.source)) {
      const parentNode = nodes.find(n => n.id === parentLink.source);
      if (parentNode) {
        ancestors.unshift(parentNode); // Add to beginning to keep chronological order
        currentParentId = parentLink.source;
        visited.add(parentLink.source);
      } else {
        break;
      }
    } else {
      break;
    }
  }

  // Resolve direct descendants
  const children = nodes.filter(n => {
    const isChild = links.some(l => l.source === targetId && l.target === n.id);
    return isChild && n.id !== targetId;
  });

  const orderedNodes = [...ancestors, targetNode, ...children];

  return (
    <div className="relative flex flex-col items-center py-4 w-full">
      {orderedNodes.map((node, index) => {
        const isTarget = node.id === targetId;
        const hasNext = index < orderedNodes.length - 1;
        const nextNode = hasNext ? orderedNodes[index + 1] : null;
        const linkToNext = nextNode ? links.find(l => l.source === node.id && l.target === nextNode.id || l.source === nextNode.id && l.target === node.id) : null;

        return (
          <div key={node.id} className="w-full flex flex-col items-center">
            {/* Connection Arrow */}
            {index > 0 && (
              <div className="flex flex-col items-center my-2 text-gray-700">
                <ArrowDown className="h-4 w-4 text-emerald-500/50" />
                {linkToNext && (
                  <div className="flex flex-col items-center gap-0.5">
                    <span className="text-[9px] text-gray-400 font-semibold uppercase select-none">
                      {linkToNext.type === 'ai-modification' ? 'AI Edit' : linkToNext.type}
                    </span>
                    {linkToNext.weight !== undefined && (
                      <span className="text-[8px] text-emerald-400/80 font-mono">
                        Weight: {Math.round(linkToNext.weight * 100)}%
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Node Card */}
            <motion.div
              whileHover={{ scale: 1.01 }}
              className={`w-full max-w-lg rounded-xl border p-4 backdrop-blur-sm transition-all ${
                isTarget
                  ? 'border-emerald-500/50 bg-emerald-950/10 shadow-lg shadow-emerald-500/5'
                  : 'border-gray-800 bg-gray-900/40 hover:border-gray-700'
              }`}
            >
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="space-y-2 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="flex items-center gap-1 text-[10px] text-gray-400 bg-gray-950 px-2 py-0.5 rounded border border-gray-850 font-medium capitalize">
                      {getFileTypeIcon(node.contentType)}
                      <span>{node.contentType}</span>
                    </div>
                    {getDerivationBadge(node.derivationType)}
                    <div className="ml-auto sm:ml-0">
                      {getStatusIcon(node.status)}
                    </div>
                  </div>

                  <div>
                    <Link 
                      to={`/content/${node.id}`} 
                      className={`text-sm font-bold block hover:underline truncate ${
                        isTarget ? 'text-emerald-300' : 'text-white'
                      }`}
                    >
                      {node.title}
                    </Link>
                    <span className="text-[10px] text-gray-500 block mt-0.5 font-mono truncate">
                      Hash: {node.originalHash}
                    </span>
                    {node.activeCases && node.activeCases.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {node.activeCases.map((c) => (
                          <Link
                            key={c._id}
                            to={`/cases/${c._id}`}
                            className="inline-flex items-center gap-1 rounded bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 text-[9px] font-medium text-red-400 hover:bg-red-500/20 transition-colors"
                          >
                            <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                            <span>Case: {c.title} ({c.status})</span>
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Score Indicator Ring */}
                <div className="flex items-center gap-3 border-t border-gray-800/60 pt-3 sm:border-0 sm:pt-0 pl-0 sm:pl-4 border-l-0 sm:border-l sm:border-gray-800">
                  <div className="text-center min-w-[65px]">
                    <span className="text-[9px] text-gray-500 block font-semibold uppercase">Confidence Score</span>
                    <span className={`text-lg font-extrabold block mt-0.5 ${getTrustScoreColor(node.scores.trust)}`}>
                      {node.scores.trust}%
                    </span>
                  </div>
                  
                  {/* Miniature Score Grid */}
                  <div className="grid grid-cols-4 gap-1 text-[8px] font-semibold text-gray-400">
                    <div className="text-center bg-gray-950/50 p-1 rounded border border-gray-850 min-w-[30px]">
                      <span className="text-[6px] text-gray-500 block font-normal">AUTH</span>
                      <span className={node.scores.authenticity >= 80 ? 'text-emerald-400' : 'text-gray-400'}>{node.scores.authenticity}</span>
                    </div>
                    <div className="text-center bg-gray-950/50 p-1 rounded border border-gray-850 min-w-[30px]">
                      <span className="text-[6px] text-gray-500 block font-normal">INTEG</span>
                      <span>{node.scores.provenance}</span>
                    </div>
                    <div className="text-center bg-gray-950/50 p-1 rounded border border-gray-850 min-w-[30px]">
                      <span className="text-[6px] text-gray-500 block font-normal">AI</span>
                      <span className={node.scores.aiManipulation > 50 ? 'text-red-400' : 'text-gray-400'}>{node.scores.aiManipulation}</span>
                    </div>
                    <div className="text-center bg-gray-950/50 p-1 rounded border border-gray-850 min-w-[30px]">
                      <span className="text-[6px] text-gray-500 block font-normal">CONF</span>
                      <span className="text-blue-400">{node.scores.confidence ?? 100}</span>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        );
      })}
    </div>
  );
}
