'use strict';

const express = require('express');
const authController = require('../controllers/authController');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh', authController.refreshToken);
router.post('/logout', protect, authController.logout);
router.get('/me', protect, authController.getMe);
router.get('/users', protect, authController.getUsers);

module.exports = router;
