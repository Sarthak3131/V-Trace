'use strict';

const dotenv = require('dotenv');
const { cleanEnv, str, port } = require('envalid');

dotenv.config();

const env = cleanEnv(process.env, {
  PORT: port({ default: 5000 }),
  MONGO_URI: str(),
  JWT_SECRET: str(),
  JWT_REFRESH_SECRET: str(),
  NODE_ENV: str({ choices: ['development', 'production', 'test'], default: 'development' }),
  S3_BUCKET_NAME: str({ default: '' }),
  AWS_REGION: str({ default: 'us-east-1' }),
  AWS_ACCESS_KEY_ID: str({ default: '' }),
  AWS_SECRET_ACCESS_KEY: str({ default: '' }),
  API_URL: str({ default: 'http://localhost:5000' }),
  REDIS_HOST: str({ default: 'localhost' }),
  REDIS_PORT: port({ default: 6379 }),
  AI_SERVICE_URL: str({ default: 'http://localhost:8000' }),
  AI_PROVIDER: str({ default: 'GEMINI' }),
  GEMINI_API_KEY: str({ default: 'DUMMY_KEY' }),
  OPENROUTER_API_KEY: str({ default: '' }),
});

console.log("AI_PROVIDER:", process.env.AI_PROVIDER);
console.log(
  "GEMINI_KEY_EXISTS:",
  !!process.env.GEMINI_API_KEY &&
    process.env.GEMINI_API_KEY !== "DUMMY_KEY"
);

module.exports = {
  PORT: env.PORT,
  MONGO_URI: env.MONGO_URI,
  JWT_SECRET: env.JWT_SECRET,
  JWT_REFRESH_SECRET: env.JWT_REFRESH_SECRET,
  NODE_ENV: env.NODE_ENV,
  S3_BUCKET_NAME: env.S3_BUCKET_NAME,
  AWS_REGION: env.AWS_REGION,
  AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: env.AWS_SECRET_ACCESS_KEY,
  API_URL: env.API_URL,
  REDIS_HOST: env.REDIS_HOST,
  REDIS_PORT: env.REDIS_PORT,
  AI_SERVICE_URL: env.AI_SERVICE_URL,
  AI_PROVIDER: env.AI_PROVIDER,
  GEMINI_API_KEY: env.GEMINI_API_KEY,
  OPENROUTER_API_KEY: env.OPENROUTER_API_KEY,
};
