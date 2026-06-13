'use strict';

const User = require('../models/User');
const { logEvent } = require('../utils/auditLogger');
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require('../utils/jwt');
const { NODE_ENV } = require('../config/env');

function createHttpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function getRefreshCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };
}

function sanitizeUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
  };
}

function capRefreshTokens(tokens) {
  if (tokens.length <= 5) {
    return tokens;
  }

  return tokens.slice(tokens.length - 5);
}

async function register(req, res, next) {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return next(createHttpError(400, 'name, email and password are required'));
    }

    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const user = await User.create({ name, email, password });

    // Cryptographically log the registration action
    await logEvent({
      action: 'user-registered',
      entityType: 'User',
      entityId: user._id,
      performedBy: user._id,
      details: { name: user.name, email: user.email, role: user.role },
    });

    const accessToken = generateAccessToken({ userId: user._id.toString(), role: user.role });
    const refreshToken = generateRefreshToken({ userId: user._id.toString() });

    user.refreshTokens = capRefreshTokens([...(user.refreshTokens || []), refreshToken]);
    await user.save();

    res.cookie('refreshToken', refreshToken, getRefreshCookieOptions());

    return res.status(201).json({
      user: sanitizeUser(user),
      accessToken,
    });
  } catch (error) {
    return next(error);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(createHttpError(400, 'email and password are required'));
    }

    const user = await User.findByEmail(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.isActive === false) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    const accessToken = generateAccessToken({ userId: user._id.toString(), role: user.role });
    const refreshToken = generateRefreshToken({ userId: user._id.toString() });

    user.refreshTokens = capRefreshTokens([...(user.refreshTokens || []), refreshToken]);
    await user.save();

    res.cookie('refreshToken', refreshToken, getRefreshCookieOptions());

    return res.status(200).json({
      user: sanitizeUser(user),
      accessToken,
    });
  } catch (error) {
    return next(error);
  }
}

async function refreshToken(req, res, next) {
  try {
    const tokenFromCookie = req.cookies && req.cookies.refreshToken;

    if (!tokenFromCookie) {
      return res.status(401).json({ error: 'No refresh token' });
    }

    let decoded;
    try {
      decoded = verifyRefreshToken(tokenFromCookie);
    } catch (error) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const user = await User.findById(decoded.userId).select('+refreshTokens');
    if (!user) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    if (user.isActive === false) {
      res.clearCookie('refreshToken', {
        httpOnly: true,
        sameSite: 'strict',
        secure: NODE_ENV === 'production',
      });
      return res.status(403).json({ error: 'Account disabled' });
    }

    const tokenExists = (user.refreshTokens || []).includes(tokenFromCookie);
    if (!tokenExists) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const newAccessToken = generateAccessToken({ userId: user._id.toString(), role: user.role });
    const newRefreshToken = generateRefreshToken({ userId: user._id.toString() });

    const remainingTokens = (user.refreshTokens || []).filter((token) => token !== tokenFromCookie);
    user.refreshTokens = capRefreshTokens([...remainingTokens, newRefreshToken]);
    await user.save();

    res.cookie('refreshToken', newRefreshToken, getRefreshCookieOptions());

    return res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    return next(error);
  }
}

async function logout(req, res, next) {
  try {
    const tokenFromCookie = req.cookies && req.cookies.refreshToken;

    if (tokenFromCookie && req.user && req.user.userId) {
      const user = await User.findById(req.user.userId).select('+refreshTokens');
      if (user) {
        user.refreshTokens = (user.refreshTokens || []).filter((token) => token !== tokenFromCookie);
        await user.save();
      }
    }

    res.clearCookie('refreshToken', {
      httpOnly: true,
      sameSite: 'strict',
      secure: NODE_ENV === 'production',
    });

    return res.status(200).json({ message: 'Logged out' });
  } catch (error) {
    return next(error);
  }
}

async function getMe(req, res, next) {
  try {
    const user = await User.findById(req.user.userId).select('name email role createdAt');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    });
  } catch (error) {
    return next(error);
  }
}

async function getUsers(req, res, next) {
  try {
    const users = await User.find({}, 'name email role').sort({ name: 1 });
    return res.status(200).json({ users });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  getMe,
  getUsers,
};
