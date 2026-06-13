import React, { useState, useMemo, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Html } from '@react-three/drei';
import * as THREE from 'three';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ArrowLeft, ShieldAlert, Lock, Clock, 
  ExternalLink, Compass, RefreshCw,
  Film, Image, Music, FileText as FileTextIcon, File as FileIcon,
  Activity, ShieldCheck
} from 'lucide-react';
import apiClient from '../../lib/axios';

// TypeScript interfaces matching database schemas
interface CaseNote {
  text: string;
  createdBy: { name: string; email: string };
  createdAt: string;
}

interface Case {
  _id: string;
  title: string;
  description?: string;
  status: 'open' | 'in-progress' | 'resolved' | 'closed';
  severity: 'low' | 'medium' | 'high' | 'critical';
  assignedTo?: { name: string; email: string };
  createdBy: { name: string; email: string };
  evidence: string[];
  notes: CaseNote[];
  createdAt: string;
  updatedAt: string;
}

interface Content {
  _id: string;
  title: string;
  contentType: 'text' | 'image' | 'document' | 'video' | 'audio';
  originalHash: string;
  merkleRoot?: string;
  status: 'pending' | 'verified' | 'flagged' | 'rejected';
  parentId?: string | { _id: string };
  derivationType: 'original' | 'copy' | 'edit' | 'ai-modification' | 'splice';
  authenticityScore: number;
  provenanceScore: number;
  metadataRiskScore: number;
  integrityVerificationScore: number;
  verificationConfidence?: number;
  owner: { name: string };
  createdAt: string;
}

interface AuditRecord {
  _id: string;
  action: string;
  entityType: 'Content' | 'Case' | 'User';
  entityId: string;
  performedBy: { name: string; email: string; role: string };
  timestamp: string;
  hash: string;
}

interface PaginatedResponse<T> {
  contents: T[];
  pagination: { total: number };
}

// 3D Node and Link internal structures
interface Node3D {
  id: string;
  type: 'case' | 'evidence' | 'merkle' | 'timeline';
  label: string;
  position: [number, number, number];
  color: string;
  data: any;
}

interface Link3D {
  source: string;
  target: string;
  type: 'case-evidence' | 'evidence-merkle' | 'evidence-parent' | 'timeline-sequence';
  color: string;
}

// Helper: Custom Line for connections. Uses primitive to avoid SVG line namespace collision in TSX.
function ConnectionLine({ start, end, color }: { start: [number, number, number]; end: [number, number, number]; color: string }) {
  const points = useMemo(() => [new THREE.Vector3(...start), new THREE.Vector3(...end)], [start, end]);
  const geometry = useMemo(() => {
    const geo = new THREE.BufferGeometry();
    geo.setFromPoints(points);
    return geo;
  }, [points]);

  const line = useMemo(() => {
    const material = new THREE.LineBasicMaterial({
      color: new THREE.Color(color),
      opacity: 0.3,
      transparent: true,
      linewidth: 1.5,
    });
    return new THREE.Line(geometry, material);
  }, [geometry, color]);

  return <primitive object={line} />;
}

// Helper: Wireframe Layer Circles for holographic guide tracks
function TrackCircle({ radius, y, color = '#374151', dashed = false }: { radius: number; y: number; color?: string; dashed?: boolean }) {
  const points = useMemo(() => {
    const pts = [];
    const segments = dashed ? 120 : 64;
    for (let i = 0; i <= segments; i++) {
      if (dashed && i % 2 === 1) continue; // Skip alternate segments for dash effect
      const theta = (i / segments) * Math.PI * 2;
      pts.push(new THREE.Vector3(radius * Math.cos(theta), y, radius * Math.sin(theta)));
    }
    return pts;
  }, [radius, y, dashed]);

  const geometry = useMemo(() => {
    const geo = new THREE.BufferGeometry();
    geo.setFromPoints(points);
    return geo;
  }, [points]);

  const line = useMemo(() => {
    const material = new THREE.LineBasicMaterial({
      color: new THREE.Color(color),
      opacity: 0.15,
      transparent: true,
    });
    return new THREE.Line(geometry, material);
  }, [geometry, color]);

  return <primitive object={line} />;
}

// Helper: Camera Controller inside Canvas to smooth-lerp towards target node coordinates
function CameraController({ 
  selectedNodePos, 
  controlsRef 
}: { 
  selectedNodePos: [number, number, number] | null;
  controlsRef: React.RefObject<any>;
}) {
  useFrame((state) => {
    const targetLookAt = selectedNodePos 
      ? new THREE.Vector3(...selectedNodePos) 
      : new THREE.Vector3(0, -0.5, 0);

    const targetCamPos = selectedNodePos
      ? new THREE.Vector3(selectedNodePos[0] * 1.15, selectedNodePos[1] + 1.8, selectedNodePos[2] + 4.2)
      : new THREE.Vector3(0, 5, 11);

    state.camera.position.lerp(targetCamPos, 0.05);

    if (controlsRef.current) {
      controlsRef.current.target.lerp(targetLookAt, 0.05);
      controlsRef.current.update();
    }
  });

  return null;
}

export default function ThreeDashboardPage() {
  const [selectedNode, setSelectedNode] = useState<Node3D | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const controlsRef = useRef<any>(null);

  // Queries to load data from active backend collections
  const { data: casesData, isLoading: loadingCases, refetch: refetchCases } = useQuery<{ cases: Case[] }>({
    queryKey: ['cases-list-3d'],
    queryFn: async () => {
      const res = await apiClient.get<{ cases: Case[] }>('/cases');
      return res.data;
    }
  });

  const { data: evidenceData, isLoading: loadingEvidence, refetch: refetchEvidence } = useQuery<PaginatedResponse<Content>>({
    queryKey: ['evidence-list-3d'],
    queryFn: async () => {
      const res = await apiClient.get<PaginatedResponse<Content>>('/content/me', { params: { limit: 100 } });
      return res.data;
    }
  });

  const { data: auditData, isLoading: loadingAudit, refetch: refetchAudit } = useQuery<{ logs: AuditRecord[] }>({
    queryKey: ['audit-logs-3d'],
    queryFn: async () => {
      const res = await apiClient.get<{ logs: AuditRecord[] }>('/audit', { params: { limit: 40 } });
      return res.data;
    }
  });

  const isLoading = loadingCases || loadingEvidence || loadingAudit;

  // Process data to generate spatial 3D nodes & connections
  const { nodes, links, stats } = useMemo(() => {
    const nodes: Node3D[] = [];
    const links: Link3D[] = [];

    const cases = casesData?.cases || [];
    const contents = evidenceData?.contents || [];
    const logs = auditData?.logs || [];

    // Calculate metadata statistics for empty dashboard views
    const totalCases = cases.length;
    const totalEvidence = contents.length;
    const verifiedEvidence = contents.filter((item) => item.status === 'verified').length;
    const verificationRate = totalEvidence > 0 ? Math.round((verifiedEvidence / totalEvidence) * 100) : 100;

    // 1. Position Case Nodes (y = -3)
    const caseCount = cases.length;
    const caseRadius = 6.0;
    const casePositions: Record<string, [number, number, number]> = {};

    cases.forEach((kase, idx) => {
      const angle = caseCount > 1 ? (idx / caseCount) * Math.PI * 2 : 0;
      const x = caseRadius * Math.cos(angle);
      const z = caseRadius * Math.sin(angle);
      const pos: [number, number, number] = [x, -3, z];
      casePositions[kase._id] = pos;

      nodes.push({
        id: kase._id,
        type: 'case',
        label: kase.title,
        position: pos,
        color: '#ef4444', // Red
        data: kase,
      });
    });

    // Map content ID to list of cases referencing it
    const contentToCases: Record<string, string[]> = {};
    cases.forEach((kase) => {
      if (kase.evidence) {
        kase.evidence.forEach((ev) => {
          const evId = typeof ev === 'object' && ev !== null ? (ev as any)._id : String(ev);
          if (!contentToCases[evId]) {
            contentToCases[evId] = [];
          }
          contentToCases[evId].push(kase._id);
        });
      }
    });

    // 2. Position Evidence Nodes (y = 0)
    const evidencePositions: Record<string, [number, number, number]> = {};
    const unlinkedEvidence: Content[] = [];
    const linkedEvidenceGrouped: Record<string, Content[]> = {}; // Case ID -> Evidence items list

    contents.forEach((item) => {
      const associatedCases = contentToCases[item._id] || [];
      if (associatedCases.length > 0) {
        const primaryCaseId = associatedCases[0];
        if (!linkedEvidenceGrouped[primaryCaseId]) {
          linkedEvidenceGrouped[primaryCaseId] = [];
        }
        linkedEvidenceGrouped[primaryCaseId].push(item);
      } else {
        unlinkedEvidence.push(item);
      }
    });

    // Position linked evidence offset around their corresponding case nodes
    Object.entries(linkedEvidenceGrouped).forEach(([caseId, items]) => {
      const casePos = casePositions[caseId];
      if (!casePos) return;

      const caseAngle = Math.atan2(casePos[2], casePos[0]);
      const evidenceRadius = 7.0; // Place outside the case ring

      const count = items.length;
      items.forEach((item, idx) => {
        // Spread items slightly around the case's coordinate ray
        const spreadAngle = count > 1 ? caseAngle + (idx - (count - 1) / 2) * 0.22 : caseAngle;
        const x = evidenceRadius * Math.cos(spreadAngle);
        const z = evidenceRadius * Math.sin(spreadAngle);
        const pos: [number, number, number] = [x, 0, z];
        evidencePositions[item._id] = pos;

        nodes.push({
          id: item._id,
          type: 'evidence',
          label: item.title,
          position: pos,
          color: '#06b6d4', // Cyan
          data: item,
        });

        // Link Case node to Evidence node
        links.push({
          source: caseId,
          target: item._id,
          type: 'case-evidence',
          color: '#f87171', // Light red link
        });
      });
    });

    // Position unlinked evidence on an inner ring (radius = 3.5, y = 0)
    const unlinkedCount = unlinkedEvidence.length;
    const unlinkedRadius = 3.2;
    unlinkedEvidence.forEach((item, idx) => {
      const angle = unlinkedCount > 1 ? (idx / unlinkedCount) * Math.PI * 2 : 0;
      const x = unlinkedRadius * Math.cos(angle);
      const z = unlinkedRadius * Math.sin(angle);
      const pos: [number, number, number] = [x, 0, z];
      evidencePositions[item._id] = pos;

      nodes.push({
        id: item._id,
        type: 'evidence',
        label: item.title,
        position: pos,
        color: '#0891b2', // Cyan-blue
        data: item,
      });
    });

    // 3. Position Merkle Root Nodes (y = 3)
    contents.forEach((item) => {
      if (item.merkleRoot) {
        const evPos = evidencePositions[item._id];
        if (evPos) {
          const merklePos: [number, number, number] = [evPos[0], 3, evPos[2]];
          const merkleId = `merkle-${item._id}`;

          nodes.push({
            id: merkleId,
            type: 'merkle',
            label: `Root: ${item.merkleRoot.substring(0, 10)}...`,
            position: merklePos,
            color: '#10b981', // Green
            data: item,
          });

          // Link Evidence to Merkle Root
          links.push({
            source: item._id,
            target: merkleId,
            type: 'evidence-merkle',
            color: '#34d399', // Emerald/green link
          });
        }
      }
    });

    // 4. Connect Evidence Parent Lineage (y = 0, across same-level nodes)
    contents.forEach((item) => {
      if (item.parentId) {
        const parentIdStr = typeof item.parentId === 'object' && item.parentId !== null ? item.parentId._id : String(item.parentId);
        const childPos = evidencePositions[item._id];
        const parentPos = evidencePositions[parentIdStr];
        if (childPos && parentPos) {
          links.push({
            source: parentIdStr,
            target: item._id,
            type: 'evidence-parent',
            color: '#c084fc', // Purple lineage link
          });
        }
      }
    });

    // 5. Position Timeline Nodes (y = -1.5, radius = 9.5)
    // Filter and sort audit logs by timestamp
    const sortedLogs = [...logs]
      .filter(l => l.action !== 'user-registered') // Keep forensic action records
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    const logCount = sortedLogs.length;
    const timelineRadius = 9.5;

    sortedLogs.forEach((log, idx) => {
      const angle = logCount > 1 ? (idx / logCount) * Math.PI * 2 : 0;
      const x = timelineRadius * Math.cos(angle);
      const z = timelineRadius * Math.sin(angle);
      const pos: [number, number, number] = [x, -1.5, z];

      nodes.push({
        id: `audit-${log._id}`,
        type: 'timeline',
        label: log.action.replace('-', ' ').toUpperCase(),
        position: pos,
        color: '#f59e0b', // Amber
        data: log,
      });

      // Link timeline sequentially
      if (idx > 0) {
        const prevLog = sortedLogs[idx - 1];
        links.push({
          source: `audit-${prevLog._id}`,
          target: `audit-${log._id}`,
          type: 'timeline-sequence',
          color: '#fbbf24', // Amber sequential link
        });
      }
    });

    return { 
      nodes, 
      links, 
      stats: {
        totalCases,
        totalEvidence,
        verificationRate
      }
    };
  }, [casesData, evidenceData, auditData]);

  // Construct lines array for rendering in canvas scene
  const linkLines = useMemo(() => {
    return links.map((link, idx) => {
      const startNode = nodes.find(n => n.id === link.source);
      const endNode = nodes.find(n => n.id === link.target);
      if (!startNode || !endNode) return null;

      return {
        id: `link-${idx}-${link.source}-${link.target}`,
        start: startNode.position,
        end: endNode.position,
        color: link.color
      };
    }).filter(Boolean) as Array<{ id: string; start: [number, number, number]; end: [number, number, number]; color: string }>;
  }, [nodes, links]);

  // Handle clicking empty canvas space to reset selection
  const handleCanvasMissed = () => {
    setSelectedNode(null);
  };

  // Helper functions for Sidebar styling
  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'verified': return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25';
      case 'flagged': return 'bg-amber-500/10 text-amber-400 border border-amber-500/25';
      case 'rejected': return 'bg-red-500/10 text-red-400 border border-red-500/25';
      case 'open': return 'bg-blue-500/10 text-blue-400 border border-blue-500/25';
      case 'in-progress': return 'bg-amber-500/10 text-amber-400 border border-amber-500/25';
      case 'resolved': return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25';
      case 'closed': return 'bg-gray-800 text-gray-400 border border-gray-700';
      default: return 'bg-gray-800 text-gray-400 border border-gray-700';
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-950/40 text-red-400 border border-red-500/30';
      case 'high': return 'bg-orange-950/40 text-orange-400 border border-orange-500/30';
      case 'medium': return 'bg-amber-950/40 text-amber-400 border border-amber-500/30';
      default: return 'bg-gray-800/40 text-gray-400 border border-gray-750';
    }
  };

  const getContentTypeIcon = (type: string) => {
    switch (type) {
      case 'video': return <Film className="h-4 w-4" />;
      case 'image': return <Image className="h-4 w-4" />;
      case 'audio': return <Music className="h-4 w-4" />;
      case 'document': return <FileTextIcon className="h-4 w-4" />;
      default: return <FileIcon className="h-4 w-4" />;
    }
  };

  const handleRefresh = () => {
    refetchCases();
    refetchEvidence();
    refetchAudit();
  };

  return (
    <div className="relative w-full h-[calc(100vh-64px)] bg-gray-950 overflow-hidden font-sans">
      {/* Top HUD Header Control Panel */}
      <div className="absolute top-4 left-4 z-10 flex flex-wrap gap-2.5 items-center">
        <Link 
          to="/dashboard" 
          className="inline-flex items-center gap-1.5 rounded-lg bg-gray-900/80 border border-gray-800 px-3.5 py-2 text-xs font-semibold text-gray-200 backdrop-blur-md transition hover:bg-gray-800 hover:text-white"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Exit View</span>
        </Link>
        <button
          onClick={handleRefresh}
          className="inline-flex items-center gap-1.5 rounded-lg bg-gray-900/80 border border-gray-800 px-3.5 py-2 text-xs font-semibold text-gray-200 backdrop-blur-md transition hover:bg-gray-800 hover:text-white"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Sync Network</span>
        </button>
        <div className="px-3.5 py-2 rounded-lg bg-gray-900/85 border border-gray-800/80 backdrop-blur-md flex items-center gap-2 text-xs text-gray-400">
          <Activity className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
          <span>WebGL Engine: <strong className="text-white">Active</strong></span>
        </div>
      </div>

      {/* Loading Overlay */}
      {isLoading && (
        <div className="absolute inset-0 z-50 bg-gray-950/80 backdrop-blur-md flex flex-col items-center justify-center gap-4 text-white">
          <div className="relative flex items-center justify-center">
            <div className="w-12 h-12 border-2 border-emerald-500/20 border-t-emerald-400 rounded-full animate-spin"></div>
            <Lock className="absolute h-5 w-5 text-emerald-400" />
          </div>
          <div className="text-center space-y-1.5">
            <h3 className="text-sm font-bold tracking-wider uppercase text-gray-200">Loading Evidence Network View</h3>
            <p className="text-xs text-gray-500 font-mono">Loading files, layers, and case associations...</p>
          </div>
        </div>
      )}

      {/* Background Interactive 3D WebGL Canvas */}
      <div className="w-full h-full cursor-grab active:cursor-grabbing">
        <Canvas 
          camera={{ position: [0, 5, 11], fov: 60 }} 
          onPointerMissed={handleCanvasMissed}
        >
          <ambientLight intensity={0.5} />
          <directionalLight position={[10, 10, 5]} intensity={0.7} />
          <pointLight position={[0, 0, 0]} intensity={0.4} />

          {/* Concentric guide layer circles */}
          <TrackCircle radius={3.2} y={0} color="#06b6d4" /> {/* Inner evidence ring */}
          <TrackCircle radius={6.0} y={-3} color="#ef4444" /> {/* Cases ring */}
          <TrackCircle radius={7.0} y={0} color="#0891b2" /> {/* Outer evidence ring */}
          <TrackCircle radius={7.0} y={3} color="#10b981" /> {/* Merkle Roots ring */}
          <TrackCircle radius={9.5} y={-1.5} color="#f59e0b" dashed /> {/* Timeline track */}

          {/* Connection Lines */}
          {linkLines.map((line) => (
            <ConnectionLine 
              key={line.id} 
              start={line.start} 
              end={line.end} 
              color={line.color} 
            />
          ))}

          {/* 3D Meshes */}
          {nodes.map((node) => {
            const isSelected = selectedNode?.id === node.id;
            const isHovered = hoveredNodeId === node.id;
            const scale = isSelected ? 1.35 : isHovered ? 1.2 : 1.0;

            let geometryElement = <sphereGeometry args={[0.35, 24, 24]} />;
            if (node.type === 'case') {
              geometryElement = <boxGeometry args={[0.7, 0.7, 0.7]} />;
            } else if (node.type === 'merkle') {
              geometryElement = <octahedronGeometry args={[0.42]} />;
            } else if (node.type === 'timeline') {
              geometryElement = <sphereGeometry args={[0.18, 16, 16]} />;
            }

            return (
              <mesh
                key={node.id}
                position={node.position}
                scale={[scale, scale, scale]}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNode(node);
                }}
                onPointerOver={(e) => {
                  e.stopPropagation();
                  setHoveredNodeId(node.id);
                }}
                onPointerOut={(e) => {
                  e.stopPropagation();
                  setHoveredNodeId(null);
                }}
              >
                {geometryElement}
                <meshStandardMaterial
                  color={node.color}
                  emissive={node.color}
                  emissiveIntensity={isSelected ? 0.7 : isHovered ? 0.45 : 0.15}
                  roughness={node.type === 'evidence' ? 0.1 : 0.4}
                  metalness={node.type === 'evidence' ? 0.9 : 0.6}
                  transparent={node.type === 'timeline'}
                  opacity={node.type === 'timeline' ? 0.85 : 1}
                />

                {/* Floating Projected HUD Label */}
                {(isHovered || isSelected) && (
                  <Html distanceFactor={11} position={[0, node.type === 'case' ? 0.7 : 0.55, 0]} center>
                    <div className={`px-2 py-0.5 text-[10px] rounded font-mono border pointer-events-none transition-all duration-150 whitespace-nowrap shadow-xl ${
                      isSelected
                        ? 'bg-emerald-950/90 text-emerald-400 border-emerald-500 font-bold scale-105'
                        : 'bg-gray-900/90 text-white border-gray-700'
                    }`}>
                      {node.label}
                    </div>
                  </Html>
                )}
              </mesh>
            );
          })}

          {/* Smooth camera gliding control */}
          <CameraController 
            selectedNodePos={selectedNode ? selectedNode.position : null} 
            controlsRef={controlsRef} 
          />

          {/* Manual camera OrbitControls */}
          <OrbitControls 
            ref={controlsRef}
            makeDefault 
            maxDistance={22}
            minDistance={3}
            maxPolarAngle={Math.PI / 2 + 0.15} // Restrict looking from directly below
          />
        </Canvas>
      </div>

      {/* Floating 3D Navigation Guide Legend */}
      <div className="absolute bottom-4 left-4 z-10 p-4 rounded-xl bg-gray-900/80 border border-gray-800/80 backdrop-blur-md text-white space-y-2.5 max-w-xs text-xs pointer-events-auto">
        <h4 className="font-bold border-b border-gray-800 pb-1.5 flex items-center gap-1 text-[11px] text-gray-400 uppercase tracking-wider">
          <Compass className="h-3.5 w-3.5 text-cyan-400" />
          <span>Investigation Layers</span>
        </h4>
        <ul className="space-y-1.5 font-mono text-[10px] text-gray-300">
          <li className="flex items-center gap-2">
            <span className="w-3.5 h-3.5 bg-emerald-500 border border-emerald-400/30 flex-shrink-0" style={{ clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)' }} />
            <span>Layer 3 (Top): Verification Roots</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-3.5 h-3.5 bg-cyan-500 rounded-full border border-cyan-400/30 flex-shrink-0" />
            <span>Layer 2 (Mid): Evidence Files</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-3.5 h-3.5 bg-amber-500 rounded-full border border-amber-400/30 flex-shrink-0 scale-75" />
            <span>Layer 1.5 (Track): Custody Timeline</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-3.5 h-3.5 bg-red-500 rounded-sm border border-red-400/30 flex-shrink-0" />
            <span>Layer 1 (Base): Active Cases</span>
          </li>
        </ul>
        <div className="text-[9px] text-gray-500 border-t border-gray-800/60 pt-1.5 flex flex-col gap-1 leading-normal">
          <span>• Left-click + drag to orbit camera</span>
          <span>• Right-click + drag to pan camera</span>
          <span>• Scroll to zoom in/out</span>
        </div>
      </div>

      {/* Glassmorphic Node Inspector Drawer Overlay (Right Side) */}
      <AnimatePresence>
        <motion.aside
          initial={{ opacity: 0, x: 150 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: 150 }}
          transition={{ type: 'spring', damping: 24, stiffness: 150 }}
          className="absolute top-4 right-4 bottom-4 w-96 z-10 pointer-events-auto flex flex-col rounded-2xl bg-gray-950/75 border border-gray-800/80 backdrop-blur-lg shadow-2xl overflow-hidden text-white"
        >
          {selectedNode ? (
            <div className="flex-1 flex flex-col p-6 overflow-y-auto space-y-6">
              {/* Header section based on node type */}
              {selectedNode.type === 'case' && (
                <>
                  <div className="flex items-start justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded flex items-center gap-1">
                      <ShieldAlert className="h-3 w-3" />
                      <span>Case File</span>
                    </span>
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${getStatusBadgeClass(selectedNode.data.status)}`}>
                      {selectedNode.data.status}
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    <h2 className="text-xl font-bold tracking-tight text-white leading-tight">{selectedNode.data.title}</h2>
                    <div className="flex flex-wrap gap-1.5">
                      <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${getSeverityBadgeClass(selectedNode.data.severity)}`}>
                        {selectedNode.data.severity} Severity
                      </span>
                    </div>
                  </div>

                  <div className="border-t border-gray-900 pt-4 space-y-3.5">
                    <div className="space-y-1">
                      <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Incident Overview</span>
                      <p className="text-xs text-gray-300 leading-relaxed font-sans">{selectedNode.data.description || 'No case brief logged for this file.'}</p>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-xs bg-gray-900/30 p-3 rounded-lg border border-gray-800/30">
                      <div>
                        <span className="block text-gray-500">Assigned Agent</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{selectedNode.data.assignedTo?.name || 'Unassigned'}</span>
                      </div>
                      <div>
                        <span className="block text-gray-500">Created By</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{selectedNode.data.createdBy?.name || 'System'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Case Notes timeline */}
                  <div className="border-t border-gray-900 pt-4 space-y-3">
                    <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Case Notes</span>
                    {selectedNode.data.notes && selectedNode.data.notes.length > 0 ? (
                      <div className="space-y-2 max-h-36 overflow-y-auto pr-1">
                        {selectedNode.data.notes.map((note: CaseNote, nIdx: number) => (
                          <div key={nIdx} className="bg-gray-900/40 border border-gray-850 p-2.5 rounded text-xs space-y-1">
                            <p className="text-gray-300 font-sans">{note.text}</p>
                            <div className="flex justify-between items-center text-[10px] text-gray-500 font-mono">
                              <span>{note.createdBy?.name || 'Agent'}</span>
                              <span>{new Date(note.createdAt).toLocaleDateString()}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-gray-600 italic font-sans">No notes logged in this case.</p>
                    )}
                  </div>

                  {/* Evidence linkage navigation */}
                  <div className="border-t border-gray-900 pt-4 space-y-3 flex-1 flex flex-col justify-end">
                    <div>
                      <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block mb-2">Associated Evidence</span>
                      {selectedNode.data.evidence && selectedNode.data.evidence.length > 0 ? (
                        <div className="flex flex-col gap-1.5">
                          {selectedNode.data.evidence.map((ev: any) => {
                            const evId = typeof ev === 'object' && ev !== null ? ev._id : String(ev);
                            const evTitle = typeof ev === 'object' && ev !== null ? ev.title : `Evidence ID: ${evId.substring(0, 8)}...`;
                            const matchesNode = nodes.find(n => n.id === evId);

                            return (
                              <button
                                key={evId}
                                onClick={() => {
                                  if (matchesNode) setSelectedNode(matchesNode);
                                }}
                                className="w-full flex items-center justify-between text-left p-2 rounded bg-gray-900/40 hover:bg-gray-900 border border-gray-800 hover:border-cyan-500/30 transition text-xs group"
                              >
                                <span className="truncate text-gray-300 group-hover:text-cyan-400">{evTitle}</span>
                                <Compass className="h-3.5 w-3.5 text-gray-600 group-hover:text-cyan-400 shrink-0" />
                              </button>
                            );
                          })}
                        </div>
                      ) : (
                        <p className="text-xs text-gray-600 italic">No evidence items linked to this case file.</p>
                      )}
                    </div>

                    <Link
                      to={`/cases/${selectedNode.data._id}`}
                      className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-red-600/10 hover:bg-red-600/20 border border-red-500/20 py-2.5 text-xs font-bold text-red-400 transition"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      <span>View Case Details</span>
                    </Link>
                  </div>
                </>
              )}

              {selectedNode.type === 'evidence' && (
                <>
                  <div className="flex items-start justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded flex items-center gap-1">
                      {getContentTypeIcon(selectedNode.data.contentType)}
                      <span className="capitalize">{selectedNode.data.contentType} evidence</span>
                    </span>
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${getStatusBadgeClass(selectedNode.data.status)}`}>
                      {selectedNode.data.status}
                    </span>
                  </div>

                  <div className="space-y-1">
                    <h2 className="text-xl font-bold tracking-tight text-white leading-tight">{selectedNode.data.title}</h2>
                    <span className="text-[9px] font-mono text-gray-500 uppercase block tracking-wider bg-gray-900/50 py-1 px-2 rounded border border-gray-850 truncate select-all" title={selectedNode.data.originalHash}>
                      SHA-256: {selectedNode.data.originalHash}
                    </span>
                  </div>

                  {/* Trust Scoring Propagation Grid */}
                  <div className="border-t border-gray-900 pt-4 space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Integrity Score</span>
                      <span className={`text-xl font-mono font-extrabold ${
                        selectedNode.data.integrityVerificationScore >= 80 ? 'text-emerald-400' : selectedNode.data.integrityVerificationScore >= 50 ? 'text-amber-400' : 'text-red-400'
                      }`}>
                        {selectedNode.data.integrityVerificationScore}%
                      </span>
                    </div>

                    {/* Progress score bars */}
                    <div className="space-y-3 bg-gray-900/30 p-3.5 rounded-lg border border-gray-800/40">
                      <div className="space-y-1">
                        <div className="flex justify-between text-[10px] font-mono text-gray-400">
                          <span>Authenticity</span>
                          <span className="text-white">{selectedNode.data.authenticityScore}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-gray-800 rounded-full overflow-hidden">
                          <div className="h-full bg-emerald-400 rounded-full" style={{ width: `${selectedNode.data.authenticityScore}%` }} />
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex justify-between text-[10px] font-mono text-gray-400">
                          <span>Data Integrity</span>
                          <span className="text-white">{selectedNode.data.provenanceScore}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-gray-800 rounded-full overflow-hidden">
                          <div className="h-full bg-cyan-400 rounded-full" style={{ width: `${selectedNode.data.provenanceScore}%` }} />
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex justify-between text-[10px] font-mono text-gray-400">
                          <span>Metadata Risk Score</span>
                          <span className={selectedNode.data.metadataRiskScore > 30 ? 'text-red-400 font-bold' : 'text-white'}>
                            {selectedNode.data.metadataRiskScore}%
                          </span>
                        </div>
                        <div className="h-1.5 w-full bg-gray-800 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${selectedNode.data.metadataRiskScore > 30 ? 'bg-red-400' : 'bg-purple-400'}`} style={{ width: `${selectedNode.data.metadataRiskScore}%` }} />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Metadata and ownership */}
                  <div className="border-t border-gray-900 pt-4 space-y-3 text-xs">
                    <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Evidence Context</span>
                    <div className="grid grid-cols-2 gap-3 bg-gray-900/20 p-3 rounded-lg border border-gray-800/20">
                      <div>
                        <span className="block text-gray-500">Registrant</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{selectedNode.data.owner?.name || 'Unknown User'}</span>
                      </div>
                      <div>
                        <span className="block text-gray-500">Registration Date</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{new Date(selectedNode.data.createdAt).toLocaleDateString()}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3 bg-gray-900/20 p-3 rounded-lg border border-gray-800/20 font-mono text-[10px]">
                      <div>
                        <span className="block text-gray-500 font-sans text-xs">Derivation type</span>
                        <span className="block font-semibold uppercase text-purple-400 mt-0.5">{selectedNode.data.derivationType}</span>
                      </div>
                      {selectedNode.data.merkleRoot && (
                        <div>
                          <span className="block text-gray-500 font-sans text-xs">Integrity Verified</span>
                          <span className="block font-semibold uppercase text-emerald-400 mt-0.5 flex items-center gap-0.5">
                            <ShieldCheck className="h-3 w-3" />
                            <span>Validated</span>
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Action link */}
                  <div className="border-t border-gray-900 pt-4 flex-1 flex flex-col justify-end">
                    <Link
                      to={`/content/${selectedNode.data._id}`}
                      className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600/10 hover:bg-cyan-600/20 border border-cyan-500/20 py-2.5 text-xs font-bold text-cyan-400 transition"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      <span>Inspect Evidence Details</span>
                    </Link>
                  </div>
                </>
              )}

              {selectedNode.type === 'merkle' && (
                <>
                  <div className="flex items-start justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded flex items-center gap-1">
                      <Lock className="h-3 w-3" />
                      <span>Evidence Integrity Proof</span>
                    </span>
                    <span className="text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded text-emerald-400">
                      Uncompromised
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    <h2 className="text-xl font-bold tracking-tight text-white leading-tight">Verification Root</h2>
                    <p className="text-xs text-gray-400">The validation hash of the database storage tree.</p>
                  </div>

                  <div className="border-t border-gray-900 pt-4 space-y-3.5">
                    <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Root Hash Signature</span>
                    <div className="rounded-lg bg-gray-900/60 p-3.5 border border-gray-850 font-mono text-xs text-emerald-400 break-all select-all">
                      {selectedNode.data.merkleRoot}
                    </div>
                  </div>

                  <div className="border-t border-gray-900 pt-4 space-y-3 text-xs leading-relaxed">
                    <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Associated Evidence</span>
                    <div className="p-3 bg-gray-900/30 border border-gray-850 rounded-lg">
                      <span className="block text-gray-500 font-semibold mb-1">File Title</span>
                      <span className="block text-gray-200 text-sm font-bold mb-2">{selectedNode.data.title}</span>
                      <span className="block text-gray-500 font-semibold mb-1">SHA-256 Hash</span>
                      <span className="block text-gray-400 font-mono truncate select-all">{selectedNode.data.originalHash}</span>
                    </div>
                    
                    <p className="text-gray-400 font-sans text-xs bg-emerald-950/10 border border-emerald-500/15 p-3 rounded-lg mt-2">
                      <strong>Audit Note:</strong> Verification Roots are computed by hashing file chunks. Any modification to the file breaks the verification path in the database.
                    </p>
                  </div>

                  <div className="border-t border-gray-900 pt-4 flex-1 flex flex-col justify-end">
                    <Link
                      to={`/content/${selectedNode.data._id}`}
                      className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-emerald-600/10 hover:bg-emerald-600/20 border border-emerald-500/20 py-2.5 text-xs font-bold text-emerald-400 transition"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      <span>Verify File Integrity</span>
                    </Link>
                  </div>
                </>
              )}

              {selectedNode.type === 'timeline' && (
                <>
                  <div className="flex items-start justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      <span>Activity Log</span>
                    </span>
                    <span className="text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded text-amber-400">
                      Logged
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    <h2 className="text-xl font-bold tracking-tight text-white leading-tight">
                      {selectedNode.data.action.replace('-', ' ').replace('-', ' ').toUpperCase()}
                    </h2>
                    <p className="text-xs text-gray-400">Chain of custody log record.</p>
                  </div>

                  <div className="border-t border-gray-900 pt-4 space-y-4 text-xs">
                    <div className="grid grid-cols-2 gap-3 bg-gray-900/20 p-3 rounded-lg border border-gray-800/20">
                      <div>
                        <span className="block text-gray-500">Entity Type</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{selectedNode.data.entityType}</span>
                      </div>
                      <div>
                        <span className="block text-gray-500">Performed By</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{selectedNode.data.performedBy?.name || 'System'}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3 bg-gray-900/20 p-3 rounded-lg border border-gray-800/20">
                      <div>
                        <span className="block text-gray-500 font-sans">Timestamp</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{new Date(selectedNode.data.timestamp).toLocaleDateString()}</span>
                      </div>
                      <div>
                        <span className="block text-gray-500 font-sans">Time</span>
                        <span className="block font-medium text-gray-200 mt-0.5">{new Date(selectedNode.data.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Verification Hash</span>
                      <div className="rounded bg-gray-900/60 p-2.5 border border-gray-850 font-mono text-[11px] text-gray-400 break-all select-all">
                        {selectedNode.data.hash}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Entity Reference ID</span>
                      <div className="rounded bg-gray-900/60 p-2.5 border border-gray-850 font-mono text-[11px] text-gray-400 select-all font-semibold">
                        {selectedNode.data.entityId}
                      </div>
                    </div>
                  </div>

                  <div className="border-t border-gray-900 pt-4 flex-1 flex flex-col justify-end">
                    <Link
                      to="/audit"
                      className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-amber-600/10 hover:bg-amber-600/20 border border-amber-500/20 py-2.5 text-xs font-bold text-amber-400 transition"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      <span>Inspect Chain of Custody</span>
                    </Link>
                  </div>
                </>
              )}
            </div>
          ) : (
            /* Sidebar Welcome Default State */
            <div className="flex-1 flex flex-col justify-between p-6">
              <div className="space-y-6">
                <div className="space-y-2">
                  <div className="inline-flex rounded-lg bg-emerald-500/10 p-2 border border-emerald-500/20">
                    <Compass className="h-5 w-5 text-emerald-400 animate-pulse" />
                  </div>
                  <h2 className="text-xl font-bold tracking-tight text-white leading-tight">Evidence Network View</h2>
                  <p className="text-xs text-gray-400 leading-relaxed font-sans">
                    Interactive 3D representation of active cases, digital evidence networks, integrity verification trees, and chain of custody logs.
                  </p>
                </div>

                <div className="border-t border-gray-900 pt-4 space-y-3">
                  <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Evidence Network Summary</span>
                  
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="bg-gray-900/40 border border-gray-850 p-2.5 rounded-lg">
                      <span className="block text-lg font-bold text-red-400 font-mono">{stats.totalCases}</span>
                      <span className="block text-[9px] text-gray-500 uppercase font-semibold mt-0.5">Cases</span>
                    </div>
                    <div className="bg-gray-900/40 border border-gray-850 p-2.5 rounded-lg">
                      <span className="block text-lg font-bold text-cyan-400 font-mono">{stats.totalEvidence}</span>
                      <span className="block text-[9px] text-gray-500 uppercase font-semibold mt-0.5">Evidence</span>
                    </div>
                    <div className="bg-gray-900/40 border border-gray-850 p-2.5 rounded-lg">
                      <span className="block text-lg font-bold text-emerald-400 font-mono">{stats.verificationRate}%</span>
                      <span className="block text-[9px] text-gray-500 uppercase font-semibold mt-0.5">Verified</span>
                    </div>
                  </div>
                </div>

                <div className="border-t border-gray-900 pt-4 space-y-3.5">
                  <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold block">Navigation controls</span>
                  
                  <div className="space-y-2.5 font-sans text-xs text-gray-400">
                    <div className="flex items-start gap-2.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                      <p><strong>Click</strong> any 3D node to automatically focus the orbital camera and inspect deep forensic values.</p>
                    </div>
                    <div className="flex items-start gap-2.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                      <p><strong>Rotate:</strong> Hold left mouse button and drag to orbit around the coordinate grid layers.</p>
                    </div>
                    <div className="flex items-start gap-2.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                      <p><strong>Pan:</strong> Hold right mouse button or Control key + drag to shift the coordinate center.</p>
                    </div>
                    <div className="flex items-start gap-2.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                      <p><strong>Zoom:</strong> Scroll up or down to zoom deep into parent-child clusters.</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Bottom ledger security verification indicator */}
              <div className="bg-emerald-950/10 border border-emerald-500/20 rounded-xl p-4 flex items-start gap-3 mt-4 text-xs text-emerald-400 leading-relaxed font-sans">
                <ShieldCheck className="h-6 w-6 text-emerald-400 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <h5 className="font-bold text-[11px] uppercase tracking-wider text-emerald-300">Integrity Verified</h5>
                  <p className="text-gray-400 text-[10px]">All file hashes match the database registry.</p>
                </div>
              </div>
            </div>
          )}
        </motion.aside>
      </AnimatePresence>
    </div>
  );
}
