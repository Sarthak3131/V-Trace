'use strict';

const { verifyAccessToken } = require('../utils/jwt');
const User = require('../models/User');

async function protect(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : null;

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = verifyAccessToken(token);

    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User belonging to this token no longer exists' });
    }

    if (user.isActive === false) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    if (user.isPasswordChangedAfter(decoded.iat)) {
      return res.status(401).json({ error: 'Password recently changed. Please log in again.' });
    }

    req.user = { userId: user._id.toString(), role: user.role };
    return next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function restrictTo(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    return next();
  };
}

module.exports = {
  protect,
  restrictTo,
};
