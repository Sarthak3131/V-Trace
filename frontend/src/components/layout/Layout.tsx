import { Outlet } from 'react-router-dom';
import { motion } from 'framer-motion';
import Navbar from './Navbar';
import AIChatAssistant from './AIChatAssistant';
import ToastContainer from './ToastContainer';
import { useWebSockets } from '../../hooks/useWebSockets';

function Layout() {
  useWebSockets();

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 relative">
      <Navbar />
      <motion.main
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: 'easeOut' }}
        className="mx-auto w-full max-w-6xl px-4 py-8"
      >
        <Outlet />
      </motion.main>
      <AIChatAssistant />
      <ToastContainer />
    </div>
  );
}

export default Layout;
