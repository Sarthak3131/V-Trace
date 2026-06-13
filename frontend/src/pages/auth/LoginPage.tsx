import { type FormEvent, useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  Eye, 
  EyeOff, 
  Lock, 
  Mail, 
  ShieldCheck, 
  Cpu, 
  Fingerprint, 
  Activity, 
  AlertCircle 
} from 'lucide-react';
import apiClient from '../../lib/axios';
import { useAuthStore } from '../../store/authStore';
import type { User } from '../../types';

interface LoginResponse {
  user: User;
  accessToken: string;
}

// Custom decorative biometric scanner animation
function ScannerAnimation() {
  const [scanProgress, setScanProgress] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setScanProgress((prev) => (prev >= 100 ? 0 : prev + 1));
    }, 40);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative flex h-full w-full flex-col items-center justify-center bg-gray-950 p-8 text-center overflow-hidden">
      {/* Dynamic scan line */}
      <div 
        className="absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-emerald-400 to-transparent opacity-60 shadow-[0_0_8px_rgba(52,211,153,0.8)] z-10"
        style={{ top: `${scanProgress}%` }}
      />

      {/* Radial neon glow rings */}
      <div className="absolute h-96 w-96 rounded-full bg-emerald-500/5 blur-3xl" />
      <div className="absolute h-96 w-96 rounded-full bg-cyan-500/5 blur-3xl" />

      {/* Scanning Target Box */}
      <div className="relative flex h-64 w-64 flex-col items-center justify-center rounded-2xl border border-gray-800 bg-gray-900/10 p-6 backdrop-blur-sm">
        {/* Corner Brackets */}
        <div className="absolute -left-1 -top-1 h-6 w-6 border-l-2 border-t-2 border-emerald-400 rounded-tl" />
        <div className="absolute -right-1 -top-1 h-6 w-6 border-r-2 border-t-2 border-emerald-400 rounded-tr" />
        <div className="absolute -left-1 -bottom-1 h-6 w-6 border-l-2 border-b-2 border-emerald-400 rounded-bl" />
        <div className="absolute -right-1 -bottom-1 h-6 w-6 border-r-2 border-b-2 border-emerald-400 rounded-br" />

        {/* Dynamic biometric icon */}
        <motion.div
          animate={{ scale: [1, 1.05, 1] }}
          transition={{ repeat: Infinity, duration: 3 }}
          className="relative text-emerald-400 opacity-80"
        >
          <Fingerprint className="h-28 w-28 animate-pulse" />
        </motion.div>

        {/* Realtime Scan readouts */}
        <div className="absolute bottom-4 left-0 right-0 text-center">
          <p className="text-[10px] font-mono tracking-widest text-emerald-400 uppercase">
            Verifying Identity... {Math.round(scanProgress)}%
          </p>
        </div>
      </div>

      <div className="mt-8 max-w-sm space-y-2 relative z-20">
        <h3 className="text-lg font-bold text-white flex items-center justify-center gap-1.5">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          <span>V-Trace Security Hub</span>
        </h3>
        <p className="text-xs text-gray-400 leading-relaxed">
          Access the secure forensic registry. Connections are encrypted, and all sessions are logged for security.
        </p>
      </div>

      {/* Decorative charts */}
      <div className="absolute bottom-6 left-6 right-6 flex items-center justify-between opacity-20 font-mono text-[9px] text-cyan-400">
        <div className="flex items-center gap-1">
          <Activity className="h-3 w-3" />
          <span>SYSTEM_LATENCY: 14ms</span>
        </div>
        <div className="flex items-center gap-1">
          <Cpu className="h-3 w-3" />
          <span>SHA-256 INTEGRITY: 100%</span>
        </div>
      </div>
    </div>
  );
}

function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const setAuth = useAuthStore((state) => state.setAuth);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [forgotPasswordSent, setForgotPasswordSent] = useState(false);

  const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname || '/dashboard';

  // Load remembered email on mount
  useEffect(() => {
    const rememberedEmail = localStorage.getItem('vtrace_remembered_email');
    if (rememberedEmail) {
      setEmail(rememberedEmail);
      setRememberMe(true);
    }
  }, []);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorMessage('');
    setIsSubmitting(true);

    try {
      const response = await apiClient.post<LoginResponse>('/auth/login', { email, password });
      
      // Save or remove remembered email
      if (rememberMe) {
        localStorage.setItem('vtrace_remembered_email', email);
      } else {
        localStorage.removeItem('vtrace_remembered_email');
      }

      setAuth(response.data.user, response.data.accessToken);
      navigate(from, { replace: true });
    } catch (error: any) {
      const message = error.response?.data?.error || 'Unable to connect to authentication server. Please check configurations.';
      setErrorMessage(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleForgotPassword = (e: React.MouseEvent) => {
    e.preventDefault();
    if (!email) {
      setErrorMessage('Please enter your email address to reset password.');
      return;
    }
    setForgotPasswordSent(true);
    setErrorMessage('');
    // Timeout reset
    setTimeout(() => {
      setForgotPasswordSent(false);
    }, 6000);
  };

  return (
    <div className="mx-auto max-w-4xl overflow-hidden rounded-2xl border border-gray-800 bg-gray-900 shadow-2xl">
      <div className="grid md:grid-cols-2">
        {/* Left Side: Animated scan illustration */}
        <div className="hidden md:block border-r border-gray-800">
          <ScannerAnimation />
        </div>

        {/* Right Side: Form panel */}
        <div className="p-8 sm:p-10 flex flex-col justify-center bg-gray-900/60 backdrop-blur-md">
          <div className="space-y-1">
            <h1 className="text-3xl font-extrabold text-white tracking-tight">Sign In</h1>
            <p className="text-sm text-gray-400">Log in to secure your account, sync cases, and verify assets.</p>
          </div>

          <form onSubmit={handleSubmit} className="mt-8 space-y-5">
            {/* Email Field */}
            <div className="space-y-1.5">
              <label htmlFor="email" className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                  <Mail className="h-4 w-4" />
                </div>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="investigator@vtrace.ai"
                  disabled={isSubmitting}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950/60 py-2.5 pl-10 pr-3 text-sm text-white placeholder-gray-500 outline-none ring-emerald-400/40 transition focus:border-emerald-500/80 focus:ring-2 disabled:cursor-not-allowed disabled:opacity-60"
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label htmlFor="password" className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Password
                </label>
                <a
                  href="#"
                  onClick={handleForgotPassword}
                  className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 transition"
                >
                  Forgot Password?
                </a>
              </div>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="••••••••••••••••"
                  disabled={isSubmitting}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950/60 py-2.5 pl-10 pr-10 text-sm text-white placeholder-gray-500 outline-none ring-emerald-400/40 transition focus:border-emerald-500/80 focus:ring-2 disabled:cursor-not-allowed disabled:opacity-60"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-300"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Remember Me Toggle */}
            <div className="flex items-center">
              <input
                id="remember"
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="h-4 w-4 rounded border-gray-750 bg-gray-950 text-emerald-500 accent-emerald-500 outline-none focus:ring-0 focus:ring-offset-0"
              />
              <label htmlFor="remember" className="ml-2 text-xs font-semibold text-gray-400 select-none cursor-pointer">
                Remember me on this device
              </label>
            </div>

            {/* Status alerts */}
            {errorMessage && (
              <div className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-xs text-red-400">
                <AlertCircle className="h-4.5 w-4.5 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            {forgotPasswordSent && (
              <div className="flex items-start gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-xs text-emerald-400">
                <ShieldCheck className="h-4.5 w-4.5 shrink-0" />
                <span>If that account is registered, a password reset link was dispatched to your email.</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full flex justify-center items-center rounded-lg bg-emerald-400 py-3 text-sm font-bold text-gray-900 transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-70 shadow-lg shadow-emerald-400/5"
            >
              {isSubmitting ? (
                <div className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4 text-gray-900" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <span>Authenticating...</span>
                </div>
              ) : (
                'Login'
              )}
            </button>
          </form>

          {/* Create Account Link */}
          <p className="mt-6 text-center text-xs text-gray-500">
            Unauthorized access is strictly monitored. New to platform?{' '}
            <Link to="/register" className="font-bold text-emerald-400 hover:text-emerald-300 transition">
              Register
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
