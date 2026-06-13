'use strict';

const { PORT } = require('./config/env');
const connectDB = require('./config/db');
const app = require('./app');

let server;

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);

  if (server) {
    server.close(() => process.exit(1));
    return;
  }

  process.exit(1);
});

async function startServer() {
  await connectDB();

  server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });

  const { initWebSocket } = require('./utils/websocket');
  initWebSocket(server);
}

startServer();
