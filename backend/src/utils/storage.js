'use strict';

const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const env = require('../config/env');

const isS3Configured = Boolean(
  env.S3_BUCKET_NAME &&
  env.AWS_REGION &&
  env.AWS_ACCESS_KEY_ID &&
  env.AWS_SECRET_ACCESS_KEY
);

let s3Client = null;

if (isS3Configured) {
  s3Client = new S3Client({
    region: env.AWS_REGION,
    credentials: {
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY
    }
  });
}

/**
 * Returns upload parameters (either S3 pre-signed URL or local upload URL).
 * @param {string} fileName - Original file name
 * @param {string} fileType - MIME type of the file
 */
async function getUploadParams(fileName, fileType) {
  const fileExt = fileName.split('.').pop() || '';
  const cleanName = fileName.replace(/[^a-zA-Z0-9]/g, '_');
  const uniqueKey = `${Date.now()}-${cleanName}.${fileExt}`;

  if (isS3Configured) {
    try {
      const command = new PutObjectCommand({
        Bucket: env.S3_BUCKET_NAME,
        Key: uniqueKey,
        ContentType: fileType
      });

      const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
      const downloadUrl = `https://${env.S3_BUCKET_NAME}.s3.${env.AWS_REGION}.amazonaws.com/${uniqueKey}`;

      return {
        provider: 's3',
        method: 'PUT',
        uploadUrl,
        downloadUrl,
        key: uniqueKey,
        headers: {
          'Content-Type': fileType
        }
      };
    } catch (err) {
      console.warn('S3 URL generation failed, falling back to local storage:', err.message);
    }
  }

  // Fallback to local storage
  return {
    provider: 'local',
    method: 'POST',
    uploadUrl: `${env.API_URL}/api/content/upload-local`,
    downloadUrl: `${env.API_URL}/uploads/${uniqueKey}`,
    key: uniqueKey,
    headers: {}
  };
}

module.exports = {
  isS3Configured,
  getUploadParams
};
