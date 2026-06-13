'use strict';

const connectDB = require('./config/db');
const { Worker } = require('bullmq');
const env = require('./config/env');
const { runAnalysis, checkRedisConnection } = require('./utils/forensicQueue');
const AIAnalysisResult = require('./models/AIAnalysisResult');

async function startWorker() {
  // 1. Connect to MongoDB
  await connectDB();

  // 2. Check if Redis is running
  const isRedisAvailable = await checkRedisConnection(env.REDIS_HOST, env.REDIS_PORT);

  if (!isRedisAvailable) {
    console.error(`[Worker] Redis is not reachable at ${env.REDIS_HOST}:${env.REDIS_PORT}. Cannot start separate worker process. Exiting...`);
    process.exit(1);
  }

  console.log(`[Worker] Starting V-Trace Forensic Worker process...`);
  console.log(`[Worker] Connecting to Redis at ${env.REDIS_HOST}:${env.REDIS_PORT}`);

  const connection = {
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
  };

  const worker = new Worker('forensic', async (job) => {
    console.log(`[Worker] Processing job ${job.id} for Content: ${job.data.contentId}`);
    await runAnalysis(job.data.contentId);
    console.log(`[Worker] Job ${job.id} completed successfully.`);
  }, { connection });

  worker.on('failed', async (job, err) => {
    // Dead Letter / final failure check
    if (job && job.attemptsMade >= job.opts.attempts) {
      console.error(`[Worker] Job ${job.id} failed after ${job.opts.attempts} attempts. Final Error:`, err.message);
      await AIAnalysisResult.updateOne(
        { contentId: job.data.contentId },
        { status: 'failed', errorMessage: `Failed after all retries: ${err.message}` }
      );
    } else {
      console.warn(`[Worker] Job ${job ? job.id : 'unknown'} failed attempt ${job ? job.attemptsMade : '?'}:`, err.message);
    }
  });

  worker.on('error', (err) => {
    console.error(`[Worker] Connection or critical runtime error:`, err.message);
  });

  process.on('SIGTERM', async () => {
    console.log('[Worker] SIGTERM received. Shutting down worker gracefully...');
    await worker.close();
    process.exit(0);
  });
}

startWorker();
