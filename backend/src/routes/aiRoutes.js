'use strict';

const express = require('express');
const aiController = require('../controllers/aiController');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.post('/chat', protect, aiController.handleChat);

router.get('/debug', protect, (req, res) => {
  return res.json(aiController.getLastChatDebugInfo());
});

router.get('/status', protect, (req, res) => {
  const { isProviderConfigured } = require('../utils/aiProvider');
  const provider = (process.env.AI_PROVIDER || 'GEMINI').toUpperCase();
  const online = isProviderConfigured();

  return res.json({
    provider: online ? (provider === 'GEMINI' ? 'Gemini' : 'OpenRouter') : 'Offline Engine',
    online: online,
    model: online ? 'gemini-2.5-flash' : 'offline'
  });
});

router.get('/health', async (req, res) => {
  try {
    const { GoogleGenerativeAI } = require("@google/generative-ai");
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash"
    });
    const result = await model.generateContent("Say Hello");
    return res.json({
      success: true,
      text: result.response.text()
    });
  } catch (error) {
    console.error("AI HEALTH ROUTE ERROR:", error);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
