import { type FormEvent, useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  User as UserIcon, 
  Mail, 
  Lock, 
  Cpu, 
  AlertCircle,
  Activity,
  Fingerprint
} from 'lucide-react';
import apiClient from '../../lib/axios';
import { useAuthStore } from '../../store/authStore';
import type { User } from '../../types';

interface RegisterResponse {
  user: User;
  accessToken: string;
}

// Procedural SVG Avatars
const AVATAR_GLYPHS = [
  {
    id: 'avatar_1',
    svg: (
      <svg className="h-10 w-10 text-emerald-400" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="40" stroke="currentColor" strokeWidth="2" strokeDasharray="4 4" />
        <rect x="35" y="35" width="30" height="30" stroke="currentColor" strokeWidth="2" />
        <circle cx="50" cy="50" r="6" fill="currentColor" />
      </svg>
    )
  },
  {
    id: 'avatar_2',
    svg: (
      <svg className="h-10 w-10 text-cyan-400" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="40" stroke="currentColor" strokeWidth="2" />
        <line x1="10" y1="50" x2="90" y2="50" stroke="currentColor" strokeWidth="1" />
        <line x1="50" y1="10" x2="50" y2="90" stroke="currentColor" strokeWidth="1" />
        <polygon points="50,30 65,55 35,55" stroke="currentColor" strokeWidth="2" />
      </svg>
    )
  },
  {
    id: 'avatar_3',
    svg: (
      <svg className="h-10 w-10 text-indigo-400" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="20" y="20" width="60" height="60" rx="10" stroke="currentColor" strokeWidth="2" />
        <circle cx="50" cy="50" r="20" stroke="currentColor" strokeWidth="2" strokeDasharray="6 3" />
        <line x1="30" y1="30" x2="70" y2="70" stroke="currentColor" strokeWidth="1" />
      </svg>
    )
  },
  {
    id: 'avatar_4',
    svg: (
      <svg className="h-10 w-10 text-purple-400" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <polygon points="50,15 80,45 80,75 50,90 20,75 20,45" stroke="currentColor" strokeWidth="2" />
        <circle cx="50" cy="52" r="14" stroke="currentColor" strokeWidth="2" />
        <line x1="50" y1="15" x2="50" y2="90" stroke="currentColor" strokeWidth="1" />
      </svg>
    )
  }
];

function RegisterPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((state) => state.setAuth);

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<'user' | 'moderator'>('user');
  const [selectedAvatar, setSelectedAvatar] = useState('avatar_1');
  const [termsAccepted, setTermsAccepted] = useState(false);

  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [passwordStrength, setPasswordStrength] = useState({ score: 0, text: 'Empty', color: 'bg-gray-800' });
  const [emailValid, setEmailValid] = useState(true);

  // Validate email structure
  useEffect(() => {
    if (!email) {
      setEmailValid(true);
      return;
    }
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    setEmailValid(regex.test(email));
  }, [email]);

  // Compute password complexity
  useEffect(() => {
    if (!password) {
      setPasswordStrength({ score: 0, text: 'Empty', color: 'bg-gray-800' });
      return;
    }

    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    let text = 'Weak';
    let color = 'bg-red-500';

    if (score >= 4) {
      text = 'Strong';
      color = 'bg-emerald-400';
    } else if (score >= 2) {
      text = 'Medium';
      color = 'bg-yellow-400';
    }

    setPasswordStrength({ score, text, color });
  }, [password]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorMessage('');

    if (!emailValid) {
      setErrorMessage('Please enter a valid email address.');
      return;
    }

    if (password.length < 8) {
      setErrorMessage('Password must be at least 8 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage('Password confirmations do not match.');
      return;
    }

    if (!termsAccepted) {
      setErrorMessage('You must agree to the terms and auditing policies.');
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await apiClient.post<RegisterResponse>('/auth/register', {
        name,
        email,
        password,
        role,
        avatarId: selectedAvatar
      });

      setAuth(response.data.user, response.data.accessToken);
      navigate('/dashboard', { replace: true });
    } catch (error: any) {
      const message = error.response?.data?.error || 'Registration failed. This email may already be in use.';
      setErrorMessage(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl overflow-hidden rounded-2xl border border-gray-800 bg-gray-900 shadow-2xl">
      <div className="grid md:grid-cols-2">
        {/* Left Side */}
        <div className="hidden md:flex flex-col justify-between bg-gray-950 p-8 border-r border-gray-800 text-center relative overflow-hidden">
          <div className="absolute h-96 w-96 rounded-full bg-emerald-500/5 blur-3xl -left-20 -top-20" />
          
          <div className="space-y-3 relative z-10 pt-6">
            <div className="mx-auto flex w-fit items-center gap-1.5 rounded-full border border-cyan-500/30 bg-cyan-500/5 px-4 py-1.5 text-[10px] font-semibold text-cyan-400 uppercase tracking-widest">
              <Activity className="h-3.5 w-3.5 animate-pulse" />
              <span>Register Account</span>
            </div>
            <h2 className="text-2xl font-extrabold text-white">Select Profile Icon</h2>
            <p className="text-xs text-gray-400 max-w-xs mx-auto">Select an icon to represent your profile.</p>
            
            {/* Avatar Selector Grid */}
            <div className="flex justify-center gap-4 pt-4">
              {AVATAR_GLYPHS.map((avatar) => (
                <button
                  key={avatar.id}
                  type="button"
                  onClick={() => setSelectedAvatar(avatar.id)}
                  className={`rounded-xl border p-2.5 transition backdrop-blur-sm ${selectedAvatar === avatar.id ? 'border-emerald-400 bg-emerald-500/10 shadow-[0_0_10px_rgba(52,211,153,0.25)]' : 'border-gray-800 bg-gray-900/40 hover:border-gray-700'}`}
                >
                  {avatar.svg}
                </button>
              ))}
            </div>
          </div>

          {/* Interactive Role badge select */}
          <div className="relative z-10 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-400">Account Role</h3>
            <div className="flex justify-center gap-2">
              <button
                type="button"
                onClick={() => setRole('user')}
                className={`flex flex-col items-center justify-center rounded-xl border px-4 py-3.5 w-32 transition ${role === 'user' ? 'border-emerald-400 bg-emerald-500/10' : 'border-gray-800 bg-gray-900/20 hover:border-gray-700'}`}
              >
                <Cpu className="h-4.5 w-4.5 text-emerald-400 mb-1" />
                <span className="text-[11px] font-bold text-white uppercase tracking-wider">Forensic Analyst</span>
              </button>
              <button
                type="button"
                onClick={() => setRole('moderator')}
                className={`flex flex-col items-center justify-center rounded-xl border px-4 py-3.5 w-32 transition ${role === 'moderator' ? 'border-cyan-400 bg-cyan-500/10' : 'border-gray-800 bg-gray-900/20 hover:border-gray-700'}`}
              >
                <Fingerprint className="h-4.5 w-4.5 text-cyan-400 mb-1" />
                <span className="text-[11px] font-bold text-white uppercase tracking-wider">Audit Supervisor</span>
              </button>
            </div>
            <p className="text-[10px] text-gray-500 max-w-xs mx-auto leading-relaxed">
              {role === 'user' 
                ? 'Authorized to upload content, run metadata integrity audits, and organize case folders.'
                : 'Authorized to review audit logs and verify data integrity.'}
            </p>
          </div>

          <div className="text-[10px] font-mono text-gray-600 relative z-10 pb-4">
            V-TRACE AUDITING SYSTEM ACTIVE
          </div>
        </div>

        {/* Right Side: Form panel */}
        <div className="p-8 sm:p-10 flex flex-col justify-center bg-gray-900/60 backdrop-blur-md">
          <div className="space-y-1">
            <h1 className="text-3xl font-extrabold text-white tracking-tight">Create Account</h1>
            <p className="text-sm text-gray-400">Create an account to access the V-Trace platform.</p>
          </div>

          <form onSubmit={handleSubmit} className="mt-6 space-y-4">
            {/* Name Field */}
            <div className="space-y-1">
              <label htmlFor="name" className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Full Name
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                  <UserIcon className="h-4 w-4" />
                </div>
                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  placeholder="Your Name"
                  disabled={isSubmitting}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950/60 py-2 pl-10 pr-3 text-sm text-white placeholder-gray-500 outline-none ring-emerald-400/40 transition focus:border-emerald-500/80 focus:ring-2 disabled:cursor-not-allowed disabled:opacity-60"
                />
              </div>
            </div>

            {/* Email Field */}
            <div className="space-y-1">
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
                  className={`w-full rounded-lg border py-2 pl-10 pr-3 text-sm text-white placeholder-gray-500 outline-none ring-emerald-400/40 transition focus:ring-2 disabled:cursor-not-allowed disabled:opacity-60 ${emailValid ? 'border-gray-700 focus:border-emerald-500/80' : 'border-red-500 focus:border-red-400'}`}
                />
              </div>
              {!emailValid && <p className="text-[10px] text-red-400">Invalid email format.</p>}
            </div>

            {/* Password Field */}
            <div className="space-y-1">
              <label htmlFor="password" className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="At least 8 characters"
                  disabled={isSubmitting}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950/60 py-2 pl-10 pr-3 text-sm text-white placeholder-gray-500 outline-none ring-emerald-400/40 transition focus:border-emerald-500/80 focus:ring-2 disabled:cursor-not-allowed disabled:opacity-60"
                />
              </div>
              
              {/* Password strength meter */}
              {password && (
                <div className="space-y-1 pt-1">
                  <div className="flex justify-between items-center text-[10px] font-semibold text-gray-400">
                    <span>Password Strength Score: {passwordStrength.score}/5</span>
                    <span className="uppercase">{passwordStrength.text}</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-gray-950 overflow-hidden flex gap-0.5">
                    {[1, 2, 3, 4, 5].map((idx) => (
                      <div 
                        key={idx}
                        className={`h-full flex-1 transition-colors duration-300 ${idx <= passwordStrength.score ? passwordStrength.color : 'bg-gray-800'}`}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Confirm Password Field */}
            <div className="space-y-1">
              <label htmlFor="confirmPassword" className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Confirm Password
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  placeholder="Repeat password"
                  disabled={isSubmitting}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950/60 py-2 pl-10 pr-3 text-sm text-white placeholder-gray-500 outline-none ring-emerald-400/40 transition focus:border-emerald-500/80 focus:ring-2 disabled:cursor-not-allowed disabled:opacity-60"
                />
              </div>
            </div>

            {/* Terms Consensus Checkbox */}
            <div className="flex items-start">
              <input
                id="terms"
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                className="h-4 w-4 mt-0.5 rounded border-gray-750 bg-gray-950 text-emerald-500 accent-emerald-500 outline-none focus:ring-0 focus:ring-offset-0"
              />
              <label htmlFor="terms" className="ml-2 text-[11px] text-gray-400 select-none cursor-pointer leading-normal">
                I agree to the V-Trace terms of service and audit log policies.
              </label>
            </div>

            {/* Error Message Box */}
            {errorMessage && (
              <div className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-xs text-red-400">
                <AlertCircle className="h-4.5 w-4.5 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full flex justify-center items-center rounded-lg bg-emerald-400 py-2.5 text-sm font-bold text-gray-950 transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-70 shadow-lg shadow-emerald-400/5"
            >
              {isSubmitting ? (
                <div className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4 text-gray-950" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <span>Registering...</span>
                </div>
              ) : (
                'Register'
              )}
            </button>
          </form>

          {/* SignIn Link */}
          <p className="mt-5 text-center text-xs text-gray-500">
            Already registered?{' '}
            <Link to="/login" className="font-bold text-emerald-400 hover:text-emerald-300 transition">
              Login
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default RegisterPage;
