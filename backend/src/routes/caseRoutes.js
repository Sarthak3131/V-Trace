'use strict';

const express = require('express');
const { protect } = require('../middleware/auth');
const {
  getCases,
  getCaseById,
  createCase,
  updateCase,
  addNote,
  linkEvidence,
} = require('../controllers/caseController');

const router = express.Router();

// Apply auth middleware to all case routes
router.use(protect);

router.route('/')
  .get(getCases)
  .post(createCase);

router.route('/:id')
  .get(getCaseById)
  .patch(updateCase);

router.post('/:id/notes', addNote);
router.post('/:id/evidence', linkEvidence);

module.exports = router;
