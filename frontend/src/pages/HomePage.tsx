import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import { 
  Shield, 
  Cpu, 
  Layers, 
  Lock, 
  ArrowRight, 
  ChevronDown, 
  Zap, 
  Fingerprint
} from 'lucide-react';

// Canvas Particle Network for background decoration
function ParticleCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;
    let width = (canvas.width = canvas.offsetWidth);
    let height = (canvas.height = canvas.offsetHeight);

    const particles: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
    }> = [];

    const particleCount = Math.min(80, Math.floor((width * height) / 15000));

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.6,
        vy: (Math.random() - 0.5) * 0.6,
        radius: Math.random() * 2 + 1,
      });
    }

    let mouse = { x: -1000, y: -1000 };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
    };

    const handleMouseLeave = () => {
      mouse.x = -1000;
      mouse.y = -1000;
    };

    window.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('mouseleave', handleMouseLeave);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth;
      height = canvas.height = canvas.offsetHeight;
    };

    window.addEventListener('resize', handleResize);

    const draw = () => {
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = 'rgba(16, 185, 129, 0.05)';
      ctx.strokeStyle = 'rgba(16, 185, 129, 0.05)';

      // Draw connections
      for (let i = 0; i < particles.length; i++) {
        const p1 = particles[i];

        // Update positions
        p1.x += p1.vx;
        p1.y += p1.vy;

        // Boundary bounce
        if (p1.x < 0 || p1.x > width) p1.vx *= -1;
        if (p1.y < 0 || p1.y > height) p1.vy *= -1;

        // Draw particle
        ctx.beginPath();
        ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(16, 185, 129, 0.3)';
        ctx.fill();

        // Check distance to mouse
        const dxMouse = p1.x - mouse.x;
        const dyMouse = p1.y - mouse.y;
        const distMouse = Math.sqrt(dxMouse * dxMouse + dyMouse * dyMouse);
        if (distMouse < 150) {
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = `rgba(52, 211, 153, ${0.15 * (1 - distMouse / 150)})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }

        // Connections to other particles
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 100) {
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(16, 185, 129, ${0.08 * (1 - dist / 100)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }

      animationId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('mouseleave', handleMouseLeave);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 h-full w-full opacity-60" />;
}

// Animated stats counter
function AnimatedCounter({ value, duration = 2000, suffix = '' }: { value: number; duration?: number; suffix?: string }) {
  const [count, setCount] = useState(0);

  useEffect(() => {
    let startTimestamp: number | null = null;
    const step = (timestamp: number) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      setCount(Math.floor(progress * value));
      if (progress < 1) {
        window.requestAnimationFrame(step);
      }
    };
    window.requestAnimationFrame(step);
  }, [value, duration]);

  return <span>{count.toLocaleString()}{suffix}</span>;
}

// FAQ item accordian component
function FAQItem({ question, answer }: { question: string; answer: string }) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="border-b border-gray-800 py-4">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex w-full items-center justify-between text-left font-medium text-white transition hover:text-emerald-400"
      >
        <span className="text-base sm:text-lg">{question}</span>
        <ChevronDown className={`h-5 w-5 text-gray-500 transition-transform duration-300 ${isOpen ? 'rotate-180 text-emerald-400' : ''}`} />
      </button>
      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <p className="mt-2 text-sm text-gray-400 leading-relaxed pr-6">{answer}</p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function HomePage() {
  const features = [
    {
      icon: <Fingerprint className="h-6 w-6 text-emerald-400" />,
      title: 'Metadata Integrity Audit',
      desc: 'Verify if files contain EXIF software signatures, active javascript scripts, or header anomalies with detailed confidence ratings.'
    },
    {
      icon: <Layers className="h-6 w-6 text-cyan-400" />,
      title: 'Activity History Logs',
      desc: 'Track file ownership, validation events, and audit logs chronologically in a secure, linked database.'
    },
    {
      icon: <Cpu className="h-6 w-6 text-indigo-400" />,
      title: 'AI Copilot Assistant',
      desc: 'Query cases using natural language, construct event timelines, and analyze file authenticity risk profiles.'
    },
    {
      icon: <Lock className="h-6 w-6 text-purple-400" />,
      title: 'Evidence Verification',
      desc: 'Secure evidence records in the registry. Generate public verification links using cryptographic signatures.'
    }
  ];

  const workflowSteps = [
    {
      step: '01',
      title: 'Upload & Calculate Hash',
      desc: 'Upload files through secure channels. The system calculates a unique SHA-256 hash to verify file integrity.'
    },
    {
      step: '02',
      title: 'Metadata Verification Layer',
      desc: 'Heuristics algorithms analyze file structures, EXIF headers, active scripts, and metadata properties for signs of tampering.'
    },
    {
      step: '03',
      title: 'Audit Log Logging',
      desc: 'Verification logs are saved. All case events and log history are linked together securely in the registry.'
    }
  ];

  return (
    <div className="space-y-24 pb-16">
      {/* Hero Section */}
      <section className="relative overflow-hidden rounded-2xl border border-gray-800 bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950 px-4 py-20 text-center shadow-2xl sm:px-10 md:py-28">
        <ParticleCanvas />
        <div className="pointer-events-none absolute -left-20 -top-20 h-64 w-64 rounded-full bg-emerald-500/10 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-24 -right-20 h-72 w-72 rounded-full bg-cyan-500/10 blur-3xl" />

        <div className="relative mx-auto max-w-4xl space-y-6">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.4 }}
            className="mx-auto flex w-fit items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/5 px-4 py-1.5 text-xs font-semibold text-emerald-400 backdrop-blur-sm"
          >
            <Zap className="h-3.5 w-3.5 animate-pulse" />
            <span>V-Trace Verification System Active</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-4xl font-extrabold tracking-tight text-white sm:text-6xl"
          >
            Verify Digital Evidence and{' '}
            <span className="bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
              Audit Metadata
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="mx-auto max-w-2xl text-base text-gray-400 sm:text-lg leading-relaxed"
          >
            Protect evidence integrity, audit metadata anomalies, and establish verifiable content history using our secure registry and analysis tools.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col items-center justify-center gap-3.5 sm:flex-row pt-4"
          >
            <Link
              to="/verify"
              className="group flex items-center gap-1.5 rounded-lg bg-emerald-400 px-6 py-3 text-sm font-bold text-gray-900 transition hover:bg-emerald-300 shadow-lg shadow-emerald-400/10"
            >
              <span>Verify Evidence</span>
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </Link>
            <Link
              to="/register"
              className="rounded-lg border border-gray-700 bg-gray-900/50 px-6 py-3 text-sm font-bold text-white transition hover:border-gray-500 hover:bg-gray-800/80 backdrop-blur-sm"
            >
              Sign In
            </Link>
          </motion.div>
        </div>
      </section>

      {/* Interactive Stats Grid */}
      <section className="mx-auto max-w-6xl px-4">
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: 'Evidence Records Verified', val: 184000, suffix: '+', color: 'text-emerald-400' },
            { label: 'Metadata Audit Accuracy', val: 99.8, suffix: '%', color: 'text-cyan-400' },
            { label: 'Active Investigation Cases', val: 1250, suffix: '', color: 'text-indigo-400' },
            { label: 'Signature Verification Time', val: 24, suffix: 'ms Average', color: 'text-purple-400' }
          ].map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.1 }}
              className="rounded-xl border border-gray-900 bg-gray-900/30 p-5 text-center backdrop-blur-sm"
            >
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{stat.label}</p>
              <p className={`mt-2 text-2xl font-extrabold sm:text-3xl ${stat.color}`}>
                <AnimatedCounter value={stat.val} suffix={stat.suffix} />
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Core Features Grid */}
      <section className="mx-auto max-w-6xl px-4 space-y-12">
        <div className="text-center space-y-3">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">Features & Capabilities</h2>
          <p className="text-sm text-gray-400 max-w-xl mx-auto">Verify files, track audit logs, and search evidence registers. Built for security analysts, legal teams, and corporate verification.</p>
        </div>

        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((feat, i) => (
            <motion.article
              key={feat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.1 }}
              whileHover={{ y: -5 }}
              className="flex flex-col justify-between rounded-xl border border-gray-900 bg-gray-900/30 p-6 transition hover:border-gray-800/80 hover:bg-gray-900/50 shadow-sm"
            >
              <div className="space-y-4">
                <div className="w-fit rounded-lg bg-gray-950 p-2.5 border border-gray-850">
                  {feat.icon}
                </div>
                <h3 className="text-lg font-bold text-white leading-snug">{feat.title}</h3>
                <p className="text-xs text-gray-400 leading-relaxed">{feat.desc}</p>
              </div>
            </motion.article>
          ))}
        </div>
      </section>

      {/* Interactive Timeline Workflow */}
      <section className="mx-auto max-w-5xl px-4 space-y-12">
        <div className="text-center space-y-3">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">How V-Trace Works</h2>
          <p className="text-sm text-gray-400 max-w-xl mx-auto">A standard three-step workflow to verify, analyze, and log evidence.</p>
        </div>

        <div className="relative grid gap-8 md:grid-cols-3 md:gap-4">
          {workflowSteps.map((item) => (
            <div key={item.step} className="relative flex flex-col items-center text-center p-6 bg-gray-900/20 rounded-xl border border-gray-900">
              <span className="text-4xl font-extrabold text-emerald-500/20 absolute top-4 left-4 select-none">{item.step}</span>
              <div className="mt-8 space-y-3">
                <h3 className="text-lg font-bold text-white">{item.title}</h3>
                <p className="text-xs text-gray-400 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Enterprise FAQ Accordion */}
      <section className="mx-auto max-w-3xl px-4 space-y-12">
        <div className="text-center space-y-3">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">Frequently Asked Questions</h2>
          <p className="text-sm text-gray-400">Common questions about V-Trace validation and security.</p>
        </div>

        <div className="rounded-xl border border-gray-900 bg-gray-900/30 p-6 backdrop-blur-sm space-y-2">
          <FAQItem 
            question="How does V-Trace verify file integrity?"
            answer="V-Trace generates a cryptographic signature (hash) for each file on upload. If a file is altered, its hash will change, immediately flagging the file as modified."
          />
          <FAQItem 
            question="What alterations can the system detect?"
            answer="Our system scans for EXIF software signatures, active scripts, revision history depth, compression anomalies, and metadata alterations."
          />
          <FAQItem 
            question="Can V-Trace be integrated into existing systems?"
            answer="Yes, V-Trace exposes standard REST APIs, making it easy to integrate verification, upload, and log features into existing CMS or legal databases."
          />
        </div>
      </section>

      {/* Call to Action Metallic Panel */}
      <section className="mx-auto max-w-5xl px-4">
        <div className="relative overflow-hidden rounded-2xl border border-gray-800 bg-gradient-to-r from-gray-950 via-gray-900 to-gray-950 p-8 sm:p-12 text-center shadow-xl">
          <div className="pointer-events-none absolute -left-20 -top-20 h-52 w-52 rounded-full bg-emerald-500/5 blur-3xl" />
          <div className="pointer-events-none absolute -bottom-20 -right-20 h-52 w-52 rounded-full bg-cyan-500/5 blur-3xl" />
          
          <div className="relative max-w-2xl mx-auto space-y-6">
            <h2 className="text-3xl font-bold text-white sm:text-4xl">Secure Your Evidence Registry</h2>
            <p className="text-sm text-gray-400 leading-relaxed">
              Equip your team with activity history logging, metadata verification, and content analysis.
            </p>
            <div className="flex flex-col items-center justify-center gap-3 sm:flex-row pt-2">
              <Link
                to="/register"
                className="w-full sm:w-auto rounded-lg bg-emerald-400 px-6 py-3 text-sm font-bold text-gray-900 transition hover:bg-emerald-300"
              >
                Create Account
              </Link>
              <Link
                to="/verify"
                className="w-full sm:w-auto rounded-lg border border-gray-750 bg-gray-950/60 px-6 py-3 text-sm font-bold text-white hover:bg-gray-900 hover:border-gray-600"
              >
                Search Registry
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="mx-auto max-w-6xl px-4 border-t border-gray-900 pt-10 text-gray-500 text-xs">
        <div className="flex flex-col gap-6 sm:flex-row sm:justify-between sm:items-center">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <Shield className="h-4.5 w-4.5 text-emerald-400" />
              <span>V-Trace AI</span>
            </div>
            <p className="max-w-xs text-gray-500 leading-relaxed">
              Verify digital evidence and secure activity history logs.
            </p>
          </div>

          <div className="flex flex-wrap gap-x-8 gap-y-2 text-gray-400 font-semibold">
            <Link to="/verify" className="hover:text-emerald-400 transition">Verification Portal</Link>
            <Link to="/login" className="hover:text-emerald-400 transition">Login Portal</Link>
            <a href="#" className="hover:text-emerald-400 transition">Developer APIs</a>
            <a href="#" className="hover:text-emerald-400 transition">System Status</a>
          </div>
        </div>
        <div className="mt-8 pt-6 border-t border-gray-950 flex flex-col gap-4 sm:flex-row sm:justify-between text-[11px]">
          <p>&copy; {new Date().getFullYear()} V-Trace AI Inc. All rights reserved. All system activities are securely logged.</p>
          <div className="flex gap-4">
            <a href="#" className="hover:underline">Privacy Policy</a>
            <a href="#" className="hover:underline">Terms of Use</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default HomePage;
