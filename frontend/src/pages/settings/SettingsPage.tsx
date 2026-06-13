import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Settings, Cpu, HardDrive, ShieldCheck, Database, ToggleLeft, ToggleRight, Sparkles } from 'lucide-react';
import apiClient from '../../lib/axios';

function SettingsPage() {
  const [aiStatus, setAiStatus] = useState({ provider: 'Offline Engine', online: false, model: 'offline' });
  const [autoRotate, setAutoRotate] = useState(true);
  const [forensicAnalysis, setForensicAnalysis] = useState(true);

  useEffect(() => {
    apiClient.get('/ai/status')
      .then(res => {
        if (res.data) setAiStatus(res.data);
      })
      .catch(() => {
        setAiStatus({ provider: 'Offline Engine', online: false, model: 'offline' });
      });
  }, []);

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 font-sans">
      {/* Title Header */}
      <div className="flex flex-col gap-1.5 border-b border-gray-800 pb-4">
        <h1 className="text-xl font-extrabold text-white tracking-tight uppercase font-mono">Settings</h1>
        <p className="text-xs text-gray-400">Manage V-Trace security configuration, AI models, and database synchronization settings.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Navigation / Selection Categories */}
        <div className="rounded-2xl border border-gray-850 bg-gray-900/40 p-4 backdrop-blur-md space-y-1.5 h-fit">
          <button className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 text-xs font-bold text-left tracking-wide uppercase font-mono">
            <Cpu className="h-4 w-4" />
            <span>AI Copilot Engine</span>
          </button>
          <button className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-gray-400 hover:bg-gray-800/40 hover:text-white text-xs font-semibold text-left transition uppercase font-mono">
            <HardDrive className="h-4 w-4" />
            <span>Integrity Nodes</span>
          </button>
          <button className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-gray-400 hover:bg-gray-800/40 hover:text-white text-xs font-semibold text-left transition uppercase font-mono">
            <ShieldCheck className="h-4 w-4" />
            <span>Security Policies</span>
          </button>
        </div>

        {/* Detailed Options panel */}
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="md:col-span-2 rounded-2xl border border-gray-850 bg-gray-900/40 p-6 backdrop-blur-md space-y-6"
        >
          {/* Section: AI Engine */}
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-white border-b border-gray-850 pb-2">
              <Sparkles className="h-4 w-4 text-emerald-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono">AI Provider Configuration</h3>
            </div>

            {/* Provider Status Display Card */}
            <div className="flex items-center justify-between p-4 rounded-xl border border-gray-800 bg-gray-950/40">
              <div className="space-y-1">
                <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest font-mono">Active Provider</span>
                <p className="text-sm font-bold text-white leading-none">{aiStatus.provider}</p>
                <p className="text-[10px] text-gray-400">Model: <code className="font-mono text-cyan-400">{aiStatus.model}</code></p>
              </div>

              <div className="flex items-center gap-2 px-3 py-1 rounded-full border border-gray-800 bg-gray-950/80">
                <span className={`h-2 w-2 rounded-full ${aiStatus.online ? 'bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]' : 'bg-amber-400'}`} />
                <span className="text-[9px] font-mono text-gray-300 uppercase tracking-widest">
                  {aiStatus.online ? 'Online' : 'Offline Mode'}
                </span>
              </div>
            </div>

            {/* Simulated Configuration options */}
            <div className="space-y-4 pt-2">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold text-gray-200">Automatically switch to Offline Engine</h4>
                  <p className="text-[10px] text-gray-400 mt-0.5">Use local dynamic intelligence patterns if the external LLM provider hits rate limits or goes offline.</p>
                </div>
                <button 
                  onClick={() => setAutoRotate(!autoRotate)}
                  className="text-gray-400 hover:text-white transition"
                >
                  {autoRotate ? (
                    <ToggleRight className="h-7 w-7 text-emerald-400" />
                  ) : (
                    <ToggleLeft className="h-7 w-7 text-gray-650" />
                  )}
                </button>
              </div>

              <div className="flex items-center justify-between border-t border-gray-850/50 pt-4">
                <div>
                  <h4 className="text-xs font-bold text-gray-200">Dynamic Forensic Analysis</h4>
                  <p className="text-[10px] text-gray-400 mt-0.5">Allow AI to auto-extract and analyze metadata anomalies during evidence library browsing.</p>
                </div>
                <button 
                  onClick={() => setForensicAnalysis(!forensicAnalysis)}
                  className="text-gray-400 hover:text-white transition"
                >
                  {forensicAnalysis ? (
                    <ToggleRight className="h-7 w-7 text-emerald-400" />
                  ) : (
                    <ToggleLeft className="h-7 w-7 text-gray-650" />
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Section: Environment parameters info */}
          <div className="space-y-3 pt-2">
            <div className="flex items-center gap-2 text-white border-b border-gray-850 pb-2">
              <Database className="h-4 w-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono">Environment Setup</h3>
            </div>
            <p className="text-[10px] text-gray-400 leading-relaxed">
              AI provider endpoints are initialized on application startup based on the system's environment variables. To change API keys, configure <code className="bg-gray-950 px-1 py-0.5 rounded text-cyan-400 text-[9px] font-mono">GEMINI_API_KEY</code> or <code className="bg-gray-950 px-1 py-0.5 rounded text-cyan-400 text-[9px] font-mono">OPENROUTER_API_KEY</code> in your environment file.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

export default SettingsPage;
