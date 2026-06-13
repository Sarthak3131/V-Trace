'use strict';

const express = require('express');
const multer = require('multer');
const atsController = require('../controllers/atsController');
const { protect } = require('../middleware/auth');

const upload = multer({
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

const uploadMiddleware = upload.fields([
  { name: 'resumeFile', maxCount: 1 },
  { name: 'jdFile', maxCount: 1 }
]);

const router = express.Router();

router.post('/analyze', protect, uploadMiddleware, atsController.analyzeResume);
router.get('/reports', protect, atsController.getMyATSReports);
router.get('/reports/:id', protect, atsController.getATSReport);
router.delete('/reports/:id', protect, atsController.deleteATSReport);

module.exports = router;
