import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  Menu, 
  ShieldCheck, 
  X, 
  Bell, 
  Check, 
  Trash2 
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { useAuthStore } from '../../store/authStore';
import { useNotificationStore } from '../../store/notificationStore';
import apiClient from '../../lib/axios';

function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const navigate = useNavigate();

  const { isAuthenticated } = useAuth();
  const clearAuth = useAuthStore((state) => state.clearAuth);

  const { 
    notifications, 
    markAsRead, 
    markAllAsRead, 
    clearAll 
  } = useNotificationStore();

  const unreadCount = notifications.filter((n) => !n.read).length;

  const handleLogout = async () => {
    try {
      await apiClient.post('/auth/logout');
    } catch {
      // Ignore logout API errors and clear client state anyway.
    } finally {
      clearAuth();
      navigate('/');
      setMobileOpen(false);
      setDropdownOpen(false);
    }
  };

  const handleNotificationClick = (id: string, link?: string) => {
    markAsRead(id);
    setDropdownOpen(false);
    if (link) {
      navigate(link);
    }
  };

  const getSeverityColor = (severity: string) => {
    if (severity === 'high') return 'bg-red-400';
    if (severity === 'medium') return 'bg-cyan-400';
    return 'bg-emerald-400';
  };

  return (
    <header className="border-b border-gray-800 bg-gray-900 text-white relative z-50 font-sans">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
        <Link to="/" className="flex items-center gap-2 text-lg font-semibold tracking-tight">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          <span>V-Trace</span>
        </Link>

        <nav className="hidden items-center gap-5 md:flex">
          <Link to="/" className="text-sm text-gray-200 transition hover:text-white">Home</Link>
          <Link to="/verify" className="text-sm text-gray-200 transition hover:text-white">Verify</Link>

          {isAuthenticated ? (
            <>
              <Link to="/dashboard" className="text-sm text-gray-200 transition hover:text-white">Dashboard</Link>
              <Link to="/content" className="text-sm text-gray-200 transition hover:text-white">Evidence Library</Link>
              <Link to="/cases" className="text-sm text-gray-200 transition hover:text-white">Cases</Link>
              <Link to="/ats" className="text-sm text-gray-200 transition hover:text-white">Resume Intel</Link>
              <Link to="/plagiarism" className="text-sm text-gray-200 transition hover:text-white">Plagiarism check</Link>
              <Link to="/audit" className="text-sm text-gray-200 transition hover:text-white">Activity History</Link>

              {/* Notification Center Trigger */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                  className="relative rounded-md p-1.5 hover:bg-gray-800 text-gray-300 hover:text-white transition"
                  aria-label="View notifications"
                >
                  <Bell className="h-5 w-5" />
                  {unreadCount > 0 && (
                    <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-emerald-500 text-[9px] font-extrabold text-gray-900 animate-pulse">
                      {unreadCount}
                    </span>
                  )}
                </button>

                {/* Notifications Dropdown Drawer */}
                {dropdownOpen && (
                  <div className="absolute right-0 mt-3 w-80 rounded-xl border border-gray-800 bg-gray-950 p-4 shadow-2xl backdrop-blur-md flex flex-col max-h-96">
                    <div className="flex items-center justify-between border-b border-gray-900 pb-2 mb-2 text-xs">
                      <span className="font-bold text-white uppercase tracking-wider">Notifications</span>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => markAllAsRead()}
                          className="hover:text-emerald-400 font-medium transition inline-flex items-center gap-0.5"
                          title="Mark all as read"
                        >
                          <Check className="h-3 w-3" />
                          <span>All</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => clearAll()}
                          className="hover:text-red-400 font-medium transition inline-flex items-center gap-0.5"
                          title="Clear all history"
                        >
                          <Trash2 className="h-3 w-3" />
                          <span>Clear</span>
                        </button>
                      </div>
                    </div>

                    {/* Scrollable notifications list */}
                    <div className="flex-1 overflow-y-auto space-y-2 max-h-60 pr-1">
                      {notifications.length === 0 ? (
                        <p className="text-[11px] text-gray-555 text-center py-6">No notifications received.</p>
                      ) : (
                        notifications.map((notif) => (
                          <div
                            key={notif.id}
                            onClick={() => handleNotificationClick(notif.id, notif.link)}
                            className={`flex gap-2.5 items-start p-2 rounded-lg border text-left cursor-pointer transition ${
                              notif.read 
                                ? 'border-gray-900/60 bg-gray-900/10 opacity-70 hover:border-gray-800' 
                                : 'border-gray-800 bg-gray-900/30 hover:border-gray-700 shadow-sm'
                            }`}
                          >
                            <span className={`h-1.5 w-1.5 mt-1.5 rounded-full shrink-0 ${getSeverityColor(notif.severity)}`} />
                            <div className="space-y-0.5 text-[11px]">
                              <span className="font-bold text-gray-200 block leading-tight">{notif.title}</span>
                              <p className="text-gray-400 leading-normal">{notif.message}</p>
                              <span className="text-[9px] text-gray-600 block mt-1 font-mono">
                                {notif.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                              </span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={handleLogout}
                className="rounded-md bg-red-500/10 border border-red-500/25 px-3 py-1.5 text-sm font-medium text-red-400 transition hover:bg-red-500/20"
              >
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" className="rounded-md border border-gray-700 px-3 py-1.5 text-sm font-medium hover:border-gray-500">Login</Link>
              <Link to="/register" className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-medium text-gray-900 transition hover:bg-emerald-400">Register</Link>
            </>
          )}
        </nav>

        <button
          type="button"
          className="inline-flex rounded-md border border-gray-700 p-2 md:hidden"
          onClick={() => setMobileOpen((prev) => !prev)}
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {mobileOpen && (
        <nav className="space-y-2 border-t border-gray-800 bg-gray-900 px-4 py-3 md:hidden">
          <Link to="/" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Home</Link>
          <Link to="/verify" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Verify</Link>

          {isAuthenticated ? (
            <>
              <Link to="/dashboard" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Dashboard</Link>
              <Link to="/content" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Evidence Library</Link>
              <Link to="/cases" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Cases</Link>
              <Link to="/ats" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Resume Intel</Link>
              <Link to="/plagiarism" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Plagiarism check</Link>
              <Link to="/audit" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Activity History</Link>
              <button
                type="button"
                onClick={handleLogout}
                className="w-full rounded-md bg-red-500 px-3 py-2 text-left text-sm font-medium text-white"
              >
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Login</Link>
              <Link to="/register" onClick={() => setMobileOpen(false)} className="block text-sm text-gray-200">Register</Link>
            </>
          )}
        </nav>
      )}
    </header>
  );
}

export default Navbar;
