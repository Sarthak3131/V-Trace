import { useEffect, useRef } from 'react';
import { useAuth } from './useAuth';
import { useNotificationStore } from '../store/notificationStore';

export function useWebSockets() {
  const { isAuthenticated } = useAuth();
  const addNotification = useNotificationStore((state) => state.addNotification);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    if (!isAuthenticated) {
      if (socketRef.current) {
        socketRef.current.close();
      }
      return;
    }

    const connect = () => {
      if (socketRef.current && socketRef.current.readyState !== WebSocket.CLOSED) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      // Dynamically resolve backend endpoint host based on active client window location
      // Aligning backend API and WebSockets host (localhost vs 127.0.0.1) prevents SameSite browser blockage
      const wsUrl = `${protocol}//${window.location.hostname}:5000/ws`;

      console.log('[WSClient] Establishing connection to:', wsUrl);
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        console.log('[WSClient] Connection established successfully.');
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current);
          reconnectTimeoutRef.current = null;
        }
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          
          if (payload.type === 'connection-status') {
            console.log('[WSClient] Status received:', payload.message);
            return;
          }

          const { event: socketEvent, data } = payload;
          console.log('[WSClient] Event received:', socketEvent, data);

          if (socketEvent === 'new-case') {
            addNotification(
              socketEvent,
              'New Case Created',
              `Case "${data.title}" created. Severity: ${data.severity.toUpperCase()}.`,
              data.severity === 'high' ? 'high' : 'medium',
              `/cases/${data._id}`
            );
          } else if (socketEvent === 'new-evidence') {
            addNotification(
              socketEvent,
              'New Evidence Uploaded',
              `Evidence file "${data.title}" uploaded. Commencing analysis.`,
              'medium',
              `/content/${data._id}`
            );
          } else if (socketEvent === 'verification-complete') {
            const isFlagged = data.status === 'flagged';
            addNotification(
              socketEvent,
              isFlagged ? 'Tampering Alert' : 'Verification Complete',
              `Verification finished for "${data.title}". Status: ${data.status.toUpperCase()} (Confidence: ${data.trustScore}%).`,
              isFlagged ? 'high' : 'low',
              `/content/${data._id}`
            );
          } else if (socketEvent === 'ai-alert') {
            addNotification(
              socketEvent,
              'AI Copilot Warning',
              `Risk signal in "${data.title}": ${data.message}`,
              data.severity || 'high',
              `/content/${data.contentId}`
            );
          }
        } catch (err) {
          console.error('[WSClient] Error parsing message payload:', err);
        }
      };

      ws.onclose = () => {
        console.log('[WSClient] Connection closed. Attempting reconnect...');
        socketRef.current = null;
        reconnectTimeoutRef.current = window.setTimeout(connect, 5000);
      };

      ws.onerror = (err) => {
        console.error('[WSClient] Error occurred:', err);
        ws.close();
      };
    };

    connect();

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [isAuthenticated, addNotification]);
}
