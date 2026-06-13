'use strict';

const express = require('express');
const multer = require('multer');
const plagiarismController = require('../controllers/plagiarismController');
const { protect } = require('../middleware/auth');

const upload = multer({
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

const router = express.Router();

router.post('/check', protect, upload.single('docFile'), plagiarismController.checkPlagiarism);
router.get('/reports', protect, plagiarismController.getMyPlagiarismReports);
router.get('/reports/:id', protect, plagiarismController.getPlagiarismReport);
router.delete('/reports/:id', protect, plagiarismController.deletePlagiarismReport);
router.get('/documents', protect, plagiarismController.getPlagiarismDocuments);

module.exports = router;
