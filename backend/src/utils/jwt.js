'use strict';

const jwt = require('jsonwebtoken');
const { JWT_SECRET, JWT_REFRESH_SECRET } = require('../config/env');

function generateAccessToken(payload) {
  return jwt.sign(
    { userId: payload.userId, role: payload.role },
    JWT_SECRET,
    { expiresIn: '15m', algorithm: 'HS256' }
  );
}

function generateRefreshToken(payload) {
  return jwt.sign(
    { userId: payload.userId },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d', algorithm: 'HS256' }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
}

function verifyRefreshToken(token) {
  return jwt.verify(token, JWT_REFRESH_SECRET, { algorithms: ['HS256'] });
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
};
