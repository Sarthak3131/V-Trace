import React from 'react';
import { motion } from 'framer-motion';
import { User as UserIcon, Shield, Mail, Calendar, Key, Award } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';

function ProfilePage() {
  const user = useAuthStore((state) => state.user);

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 font-sans">
      {/* Title Header */}
      <div className="flex flex-col gap-1.5 border-b border-gray-800 pb-4">
        <h1 className="text-xl font-extrabold text-white tracking-tight uppercase font-mono">User Profile</h1>
        <p className="text-xs text-gray-400">View and manage your V-Trace account security authorization and identity credentials.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Left Side: Avatar and Quick Info */}
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="rounded-2xl border border-gray-850 bg-gray-900/40 p-6 backdrop-blur-md flex flex-col items-center text-center space-y-4"
        >
          <div className="relative flex h-24 w-24 items-center justify-center rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <UserIcon className="h-12 w-12" />
            <span className="absolute bottom-1 right-1 flex h-4 w-4">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-4 w-4 rounded-full bg-emerald-500 border border-gray-900" />
            </span>
          </div>

          <div>
            <h2 className="text-base font-bold text-white leading-snug">{user?.name || 'Copilot Analyst'}</h2>
            <span className="inline-flex items-center gap-1 rounded bg-emerald-400/15 border border-emerald-500/20 px-2.5 py-0.5 mt-2 text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
              <Shield className="h-3 w-3" />
              {user?.role || 'Analyst'}
            </span>
          </div>

          <div className="w-full border-t border-gray-850/50 pt-4 text-xs text-gray-400 space-y-2">
            <div className="flex justify-between">
              <span>Status</span>
              <span className="text-emerald-400 font-semibold">Active</span>
            </div>
            <div className="flex justify-between">
              <span>Auth Method</span>
              <span className="font-mono text-[10px] text-gray-300">JWT Token</span>
            </div>
          </div>
        </motion.div>

        {/* Right Side: Detailed Info */}
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.15 }}
          className="md:col-span-2 rounded-2xl border border-gray-850 bg-gray-900/40 p-6 backdrop-blur-md space-y-6"
        >
          <h3 className="text-xs font-bold text-white uppercase tracking-wider border-b border-gray-850 pb-2">Account Authorization Ledger</h3>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-xl border border-gray-850 bg-gray-950/20 space-y-1.5">
              <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
                <Mail className="h-3.5 w-3.5" />
                <span>Email Address</span>
              </div>
              <p className="text-xs text-gray-200 font-medium">{user?.email || 'analyst@vtrace.com'}</p>
            </div>

            <div className="p-3.5 rounded-xl border border-gray-850 bg-gray-950/20 space-y-1.5">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold">
                <Award className="h-3.5 w-3.5" />
                <span>Security Role</span>
              </div>
              <p className="text-xs text-gray-200 font-medium capitalize">{user?.role || 'user'}</p>
            </div>

            <div className="p-3.5 rounded-xl border border-gray-850 bg-gray-950/20 space-y-1.5">
              <div className="flex items-center gap-2 text-indigo-400 text-xs font-semibold">
                <Key className="h-3.5 w-3.5" />
                <span>Access ID</span>
              </div>
              <p className="text-xs text-gray-200 font-mono text-[10px] truncate">{user?.id || '65123984e7235a298a00bc91'}</p>
            </div>

            <div className="p-3.5 rounded-xl border border-gray-850 bg-gray-950/20 space-y-1.5">
              <div className="flex items-center gap-2 text-amber-400 text-xs font-semibold">
                <Calendar className="h-3.5 w-3.5" />
                <span>Account Created</span>
              </div>
              <p className="text-xs text-gray-200 font-medium">June 2026</p>
            </div>
          </div>

          <div className="p-4 rounded-xl border border-dashed border-gray-800 bg-gray-950/10 text-xs text-gray-400 space-y-2">
            <h4 className="font-bold text-gray-300">Security Clearance Notice</h4>
            <p className="leading-relaxed">
              As an authorized investigator, you have read access to cryptographic signatures, multi-model forensics, and case documentation. All search queries, integrity checks, and navigation actions are captured on the immutable audit trail.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

export default ProfilePage;
