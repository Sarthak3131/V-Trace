'use strict';

const { WebSocketServer } = require('ws');

let wss = null;

function initWebSocket(server) {
  wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    const { pathname } = new URL(request.url, `http://${request.headers.host}`);

    if (pathname === '/ws') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  wss.on('connection', async (ws) => {
    console.log('[WS] Client connected');

    // Send welcome message
    ws.send(JSON.stringify({
      type: 'connection-status',
      message: 'V-Trace real-time notifications connected.'
    }));

    // Stream actual recent events from DB to populate telemetry on connection
    try {
      const Case = require('../models/Case');
      const Content = require('../models/Content');
      const AIAnalysisResult = require('../models/AIAnalysisResult');

      const [recentCases, recentEvidence, recentFindings] = await Promise.all([
        Case.find().sort({ createdAt: -1 }).limit(3),
        Content.find().sort({ createdAt: -1 }).limit(3),
        AIAnalysisResult.find({ status: 'completed' })
          .populate('contentId')
          .sort({ processedAt: -1 })
          .limit(3)
      ]);

      let delay = 300;

      // Stream recent cases
      recentCases.forEach((c) => {
        setTimeout(() => {
          if (ws.readyState === 1) { // 1 = OPEN
            ws.send(JSON.stringify({
              event: 'new-case',
              data: {
                _id: c._id,
                title: c.title,
                severity: c.severity,
                status: c.status
              }
            }));
          }
        }, delay);
        delay += 500;
      });

      // Stream recent evidence ingestion
      recentEvidence.forEach((ev) => {
        setTimeout(() => {
          if (ws.readyState === 1) {
            ws.send(JSON.stringify({
              event: 'new-evidence',
              data: {
                _id: ev._id,
                title: ev.title,
                contentType: ev.contentType
              }
            }));
          }
        }, delay);
        delay += 500;
      });

      // Stream verification completions and anomalies
      recentFindings.forEach((f) => {
        if (!f.contentId) return;
        
        setTimeout(() => {
          if (ws.readyState === 1) {
            ws.send(JSON.stringify({
              event: 'verification-complete',
              data: {
                _id: f.contentId._id,
                title: f.contentId.title,
                status: f.contentId.status,
                integrityVerificationScore: f.contentId.integrityVerificationScore
              }
            }));
          }
        }, delay);
        delay += 500;

        if (f.contentId.status === 'flagged') {
          setTimeout(() => {
            if (ws.readyState === 1) {
              ws.send(JSON.stringify({
                event: 'integrity-alert',
                data: {
                  contentId: f.contentId._id,
                  title: f.contentId.title,
                  message: `Altered metadata detected: ${f.metadataFindings} (Risk: ${f.metadataRiskScore}%).`,
                  severity: f.metadataRiskScore >= 75 ? 'high' : 'medium'
                }
              }));
            }
          }, delay);
          delay += 500;
        }
      });
    } catch (err) {
      console.error('[WS] Failed to load recent DB context for notification broadcast:', err.message);
    }

    ws.on('close', () => {
      console.log('[WS] Client disconnected');
    });

    ws.on('error', (err) => {
      console.error('[WS] Client connection error:', err.message);
    });
  });

  console.log('[WS] WebSocket Server bound to HTTP Upgrade handler at /ws');
  return wss;
}

function broadcast(event, data) {
  if (!wss) {
    console.warn('[WS] WebSocket Server not initialized yet.');
    return;
  }

  const payload = JSON.stringify({ event, data, timestamp: new Date() });
  
  let activeClients = 0;
  wss.clients.forEach((client) => {
    if (client.readyState === 1) { // 1 = OPEN
      client.send(payload);
      activeClients++;
    }
  });
}

module.exports = {
  initWebSocket,
  broadcast
};
