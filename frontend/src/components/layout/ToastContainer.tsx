import { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Info, AlertTriangle, ShieldCheck, X } from 'lucide-react';
import { useNotificationStore, type AppNotification } from '../../store/notificationStore';
import { useNavigate } from 'react-router-dom';

function ToastCard({ toast }: { toast: AppNotification }) {
  const removeToast = useNotificationStore((state) => state.removeToast);
  const markAsRead = useNotificationStore((state) => state.markAsRead);
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      removeToast(toast.id);
    }, 5000);
    return () => clearTimeout(timer);
  }, [toast.id, removeToast]);

  const handleToastClick = () => {
    markAsRead(toast.id);
    removeToast(toast.id);
    if (toast.link) {
      navigate(toast.link);
    }
  };

  const getIcon = () => {
    if (toast.severity === 'high') return <AlertTriangle className="h-5 w-5 text-red-400" />;
    if (toast.severity === 'medium') return <Info className="h-5 w-5 text-cyan-400" />;
    return <ShieldCheck className="h-5 w-5 text-emerald-400" />;
  };

  const getBorderColor = () => {
    if (toast.severity === 'high') return 'border-red-500/20 bg-red-500/5';
    if (toast.severity === 'medium') return 'border-cyan-500/20 bg-cyan-500/5';
    return 'border-emerald-500/20 bg-emerald-500/5';
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 50, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9, y: -20 }}
      transition={{ duration: 0.25, ease: 'easeOut' }}
      className={`relative flex w-80 cursor-pointer overflow-hidden rounded-xl border p-4 shadow-xl backdrop-blur-md ${getBorderColor()}`}
      onClick={handleToastClick}
    >
      <div className="flex gap-3 items-start pr-4">
        <div className="mt-0.5 shrink-0">
          {getIcon()}
        </div>
        <div className="space-y-1 text-left">
          <span className="block text-xs font-bold text-white uppercase tracking-wider">{toast.title}</span>
          <p className="text-[11px] text-gray-300 leading-normal">{toast.message}</p>
        </div>
      </div>

      <button
        onClick={(e) => {
          e.stopPropagation();
          removeToast(toast.id);
        }}
        className="absolute top-2 right-2 text-gray-500 hover:text-gray-300"
      >
        <X className="h-4 w-4" />
      </button>

      {/* Auto-dismiss progress bar indicator */}
      <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gray-950/20">
        <motion.div 
          initial={{ width: '100%' }}
          animate={{ width: 0 }}
          transition={{ duration: 5, ease: 'linear' }}
          className={`h-full ${
            toast.severity === 'high' ? 'bg-red-400' :
            toast.severity === 'medium' ? 'bg-cyan-400' : 'bg-emerald-400'
          }`}
        />
      </div>
    </motion.div>
  );
}

function ToastContainer() {
  const toasts = useNotificationStore((state) => state.toasts);

  return (
    <div className="fixed bottom-6 left-6 z-[60] flex flex-col gap-3">
      <AnimatePresence>
        {toasts.map((toast) => (
          <ToastCard key={toast.id} toast={toast} />
        ))}
      </AnimatePresence>
    </div>
  );
}

export default ToastContainer;
