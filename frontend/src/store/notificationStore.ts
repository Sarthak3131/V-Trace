import { create } from 'zustand';

export interface AppNotification {
  id: string;
  event: string;
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high';
  timestamp: Date;
  read: boolean;
  link?: string;
}

interface NotificationState {
  notifications: AppNotification[];
  toasts: AppNotification[];
  addNotification: (event: string, title: string, message: string, severity?: 'low' | 'medium' | 'high', link?: string) => void;
  removeToast: (id: string) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  clearAll: () => void;
}

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],
  toasts: [],
  
  addNotification: (event, title, message, severity = 'low', link) => {
    const newNotif: AppNotification = {
      id: Math.random().toString(36).substring(2, 9),
      event,
      title,
      message,
      severity,
      timestamp: new Date(),
      read: false,
      link
    };

    set((state) => {
      // Limit history to 20 items
      const updatedHistory = [newNotif, ...state.notifications].slice(0, 20);
      return {
        notifications: updatedHistory,
        toasts: [...state.toasts, newNotif]
      };
    });
  },

  removeToast: (id) => {
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id)
    }));
  },

  markAsRead: (id) => {
    set((state) => ({
      notifications: state.notifications.map((n) => n.id === id ? { ...n, read: true } : n)
    }));
  },

  markAllAsRead: () => {
    set((state) => ({
      notifications: state.notifications.map((n) => ({ ...n, read: true }))
    }));
  },

  clearAll: () => {
    set({
      notifications: [],
      toasts: []
    });
  }
}));
