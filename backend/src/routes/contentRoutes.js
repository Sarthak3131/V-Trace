'use strict';

const express = require('express');
const { body } = require('express-validator');
const contentController = require('../controllers/contentController');
const { protect, restrictTo } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const uploadsDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const finalName = req.body.key || `${Date.now()}-${file.originalname}`;
    cb(null, finalName);
  }
});

const upload = multer({ storage });

const router = express.Router();

const CONTENT_TYPES = ['text', 'image', 'document', 'video', 'audio'];

const createContentValidation = validate([
  body('title')
    .notEmpty().withMessage('title is required')
    .isLength({ min: 3, max: 200 }).withMessage('title must be between 3 and 200 characters'),
  body('originalHash')
    .notEmpty().withMessage('originalHash is required')
    .isLength({ min: 64, max: 64 }).withMessage('originalHash must be 64 characters')
    .matches(/^[0-9a-fA-F]{64}$/).withMessage('originalHash must be a valid SHA-256 hex string'),
  body('contentType')
    .notEmpty().withMessage('contentType is required')
    .isIn(CONTENT_TYPES).withMessage('contentType is invalid'),
  body('fileSize')
    .optional()
    .isInt({ min: 0 }).withMessage('fileSize must be a non-negative integer'),
  body('tags')
    .optional()
    .isArray({ max: 10 }).withMessage('tags must be an array with at most 10 items'),
]);

const updateContentValidation = validate([
  body('title')
    .optional()
    .isLength({ min: 3, max: 200 }).withMessage('title must be between 3 and 200 characters'),
  body('tags')
    .optional()
    .isArray({ max: 10 }).withMessage('tags must be an array with at most 10 items'),
]);

const uploadParamsValidation = validate([
  body('fileName').notEmpty().withMessage('fileName is required'),
  body('fileType').notEmpty().withMessage('fileType is required')
]);

router.get('/', contentController.getAllContent);
router.get('/me', protect, contentController.getMyContent);
router.get('/:id', contentController.getContentById);
router.get('/:id/provenance', contentController.getProvenanceGraph);
router.get('/:id/analysis', contentController.getContentAnalysis);
router.post('/', protect, createContentValidation, contentController.createContent);
router.post('/upload-params', protect, uploadParamsValidation, contentController.getUploadParameters);
router.post('/upload-local', protect, upload.single('file'), contentController.uploadLocalFile);
router.put('/:id', protect, updateContentValidation, contentController.updateContent);
router.delete('/:id', protect, contentController.deleteContent);
router.post('/:id/verify', protect, restrictTo('admin', 'moderator'), contentController.verifyContent);
router.post('/:id/flag', protect, restrictTo('admin', 'moderator'), contentController.flagContent);
router.post('/check-duplicate', protect, contentController.checkDuplicate);

module.exports = router;
