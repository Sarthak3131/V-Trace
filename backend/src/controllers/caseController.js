'use strict';

const Case = require('../models/Case');
const User = require('../models/User');
const { logEvent } = require('../utils/auditLogger');
const { broadcast } = require('../utils/websocket');

function createHttpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

// Get all cases (Admins/Moderators see all; ordinary users see cases they created or are assigned to)
async function getCases(req, res, next) {
  try {
    const filter = {};
    if (req.user.role !== 'admin' && req.user.role !== 'moderator') {
      filter.$or = [
        { createdBy: req.user.userId },
        { assignedTo: req.user.userId }
      ];
    }

    if (req.query.status) {
      filter.status = String(req.query.status);
    }
    if (req.query.severity) {
      filter.severity = String(req.query.severity);
    }
    if (req.query.assignedTo) {
      filter.assignedTo = String(req.query.assignedTo);
    }

    const cases = await Case.find(filter)
      .populate('assignedTo', 'name email role')
      .populate('createdBy', 'name email role')
      .sort({ createdAt: -1 });

    return res.status(200).json({ cases });
  } catch (error) {
    return next(error);
  }
}

// Get single case details
async function getCaseById(req, res, next) {
  try {
    const kase = await Case.findById(req.params.id)
      .populate('assignedTo', 'name email role')
      .populate('createdBy', 'name email role')
      .populate('evidence')
      .populate('notes.createdBy', 'name role');

    if (!kase) {
      return next(createHttpError(404, 'Case not found'));
    }

    // Access control: only creator, assignee, or admin/moderator can view
    const isOwner = kase.createdBy._id.toString() === req.user.userId;
    const isAssignee = kase.assignedTo && kase.assignedTo._id.toString() === req.user.userId;
    const isPrivileged = req.user.role === 'admin' || req.user.role === 'moderator';

    if (!isOwner && !isAssignee && !isPrivileged) {
      return next(createHttpError(403, 'Access denied'));
    }

    return res.status(200).json({ case: kase });
  } catch (error) {
    return next(error);
  }
}

// Create new case
async function createCase(req, res, next) {
  try {
    const { title, description, severity, assignedTo, evidence } = req.body;

    if (!title || title.length < 3) {
      return next(createHttpError(400, 'Title is required and must be at least 3 characters'));
    }

    let assigneeId = null;
    if (assignedTo) {
      // Ordinary users can only assign to themselves. Privileged roles can assign to anyone.
      if (req.user.role !== 'admin' && req.user.role !== 'moderator' && assignedTo !== req.user.userId) {
        return next(createHttpError(403, 'Only admins or moderators can assign cases to other users'));
      }
      const targetUser = await User.findById(assignedTo);
      if (!targetUser) {
        return next(createHttpError(400, 'Assigned user not found'));
      }
      assigneeId = targetUser._id;
    }

    const userDoc = await User.findById(req.user.userId);
    const userName = userDoc ? userDoc.name : 'Unknown User';

    const kase = await Case.create({
      title,
      description,
      severity: severity || 'medium',
      assignedTo: assigneeId,
      createdBy: req.user.userId,
      evidence: evidence || [],
      history: [{
        action: 'case-created',
        details: `Case opened by ${userName} (${req.user.role})`,
        performedBy: req.user.userId
      }]
    });

    // Cryptographically log the case creation event
    await logEvent({
      action: 'case-created',
      entityType: 'Case',
      entityId: kase._id,
      performedBy: req.user.userId,
      details: { title: kase.title, severity: kase.severity, assignedTo: kase.assignedTo }
    });

    const populatedCase = await Case.findById(kase._id)
      .populate('assignedTo', 'name email role')
      .populate('createdBy', 'name email role');

    broadcast('new-case', populatedCase);

    return res.status(201).json({ case: populatedCase });
  } catch (error) {
    return next(error);
  }
}

// Update case properties (status, severity, assignee, description)
async function updateCase(req, res, next) {
  try {
    const kase = await Case.findById(req.params.id);
    if (!kase) {
      return next(createHttpError(404, 'Case not found'));
    }

    // Access control: only creator, assignee, or admin/moderator can update
    const isOwner = kase.createdBy.toString() === req.user.userId;
    const isAssignee = kase.assignedTo && kase.assignedTo.toString() === req.user.userId;
    const isPrivileged = req.user.role === 'admin' || req.user.role === 'moderator';

    if (!isOwner && !isAssignee && !isPrivileged) {
      return next(createHttpError(403, 'Access denied'));
    }

    const { title, description, status, severity, assignedTo } = req.body;
    const historyEntries = [];

    if (title && title !== kase.title) {
      historyEntries.push({
        action: 'title-updated',
        details: `Title updated from "${kase.title}" to "${title}"`,
        performedBy: req.user.userId
      });
      kase.title = title;
    }

    if (description !== undefined && description !== kase.description) {
      historyEntries.push({
        action: 'description-updated',
        details: 'Description updated',
        performedBy: req.user.userId
      });
      kase.description = description;
    }

    if (status && status !== kase.status) {
      historyEntries.push({
        action: 'status-changed',
        details: `Status changed from "${kase.status}" to "${status}"`,
        performedBy: req.user.userId
      });
      kase.status = status;
    }

    if (severity && severity !== kase.severity) {
      historyEntries.push({
        action: 'severity-changed',
        details: `Severity changed from "${kase.severity}" to "${severity}"`,
        performedBy: req.user.userId
      });
      kase.severity = severity;
    }

    if (assignedTo !== undefined) {
      const currentAssigneeStr = kase.assignedTo ? kase.assignedTo.toString() : '';
      const newAssigneeStr = assignedTo ? assignedTo.toString() : '';
      
      if (currentAssigneeStr !== newAssigneeStr) {
        if (assignedTo) {
          // Access check: only admins/moderators can assign to others
          if (req.user.role !== 'admin' && req.user.role !== 'moderator' && assignedTo !== req.user.userId) {
            return next(createHttpError(403, 'Only admins or moderators can assign cases to other users'));
          }
          const targetUser = await User.findById(assignedTo);
          if (!targetUser) {
            return next(createHttpError(400, 'Assigned investigator user not found'));
          }
          kase.assignedTo = targetUser._id;
          historyEntries.push({
            action: 'case-assigned',
            details: `Assigned case to ${targetUser.name}`,
            performedBy: req.user.userId
          });
        } else {
          kase.assignedTo = null;
          historyEntries.push({
            action: 'case-unassigned',
            details: 'Removed assignment',
            performedBy: req.user.userId
          });
        }
      }
    }

    if (historyEntries.length > 0) {
      kase.history.push(...historyEntries);
      await kase.save();

      // Log each update to Chain of Custody
      for (const entry of historyEntries) {
        let action = 'case-updated';
        if (entry.action === 'status-changed') action = 'case-status-changed';
        else if (entry.action === 'severity-changed') action = 'case-severity-changed';
        else if (entry.action === 'case-assigned') action = 'case-assigned';
        else if (entry.action === 'case-unassigned') action = 'case-unassigned';
        else if (entry.action === 'title-updated') action = 'case-title-updated';
        else if (entry.action === 'description-updated') action = 'case-description-updated';

        await logEvent({
          action,
          entityType: 'Case',
          entityId: kase._id,
          performedBy: req.user.userId,
          details: { details: entry.details }
        });
      }
    }

    const updatedCase = await Case.findById(kase._id)
      .populate('assignedTo', 'name email role')
      .populate('createdBy', 'name email role')
      .populate('evidence')
      .populate('notes.createdBy', 'name role');

    return res.status(200).json({ case: updatedCase });
  } catch (error) {
    return next(error);
  }
}

// Add note to case log
async function addNote(req, res, next) {
  try {
    const kase = await Case.findById(req.params.id);
    if (!kase) {
      return next(createHttpError(404, 'Case not found'));
    }

    const isOwner = kase.createdBy.toString() === req.user.userId;
    const isAssignee = kase.assignedTo && kase.assignedTo.toString() === req.user.userId;
    const isPrivileged = req.user.role === 'admin' || req.user.role === 'moderator';

    if (!isOwner && !isAssignee && !isPrivileged) {
      return next(createHttpError(403, 'Access denied'));
    }

    const { text } = req.body;
    if (!text || text.trim().length === 0) {
      return next(createHttpError(400, 'Note text is required'));
    }

    const userDoc = await User.findById(req.user.userId);
    const userName = userDoc ? userDoc.name : 'Unknown User';

    kase.notes.push({
      text: text.trim(),
      createdBy: req.user.userId
    });

    kase.history.push({
      action: 'note-added',
      details: `Note added by ${userName}`,
      performedBy: req.user.userId
    });

    await kase.save();

    // Log to Chain of Custody
    await logEvent({
      action: 'case-note-added',
      entityType: 'Case',
      entityId: kase._id,
      performedBy: req.user.userId,
      details: { text: text.trim() }
    });

    const updatedCase = await Case.findById(kase._id)
      .populate('assignedTo', 'name email role')
      .populate('createdBy', 'name email role')
      .populate('evidence')
      .populate('notes.createdBy', 'name role');

    return res.status(200).json({ case: updatedCase });
  } catch (error) {
    return next(error);
  }
}

// Link/unlink evidence content ID
async function linkEvidence(req, res, next) {
  try {
    const kase = await Case.findById(req.params.id);
    if (!kase) {
      return next(createHttpError(404, 'Case not found'));
    }

    const isOwner = kase.createdBy.toString() === req.user.userId;
    const isAssignee = kase.assignedTo && kase.assignedTo.toString() === req.user.userId;
    const isPrivileged = req.user.role === 'admin' || req.user.role === 'moderator';

    if (!isOwner && !isAssignee && !isPrivileged) {
      return next(createHttpError(403, 'Access denied'));
    }

    const { contentId, action } = req.body; // action: 'link' or 'unlink'
    if (!contentId) {
      return next(createHttpError(400, 'Content ID is required'));
    }

    if (action === 'link') {
      if (kase.evidence.includes(contentId)) {
        return res.status(200).json({ case: kase });
      }
      kase.evidence.push(contentId);
      kase.history.push({
        action: 'evidence-linked',
        details: `Linked evidence ID ${contentId} to case`,
        performedBy: req.user.userId
      });
    } else if (action === 'unlink') {
      kase.evidence = kase.evidence.filter(id => id.toString() !== contentId.toString());
      kase.history.push({
        action: 'evidence-unlinked',
        details: `Unlinked evidence ID ${contentId} from case`,
        performedBy: req.user.userId
      });
    } else {
      return next(createHttpError(400, 'Invalid action parameter (must be "link" or "unlink")'));
    }

    await kase.save();

    // Log to Chain of Custody
    await logEvent({
      action: action === 'link' ? 'case-evidence-linked' : 'case-evidence-unlinked',
      entityType: 'Case',
      entityId: kase._id,
      performedBy: req.user.userId,
      details: { contentId }
    });

    const updatedCase = await Case.findById(kase._id)
      .populate('assignedTo', 'name email role')
      .populate('createdBy', 'name email role')
      .populate('evidence')
      .populate('notes.createdBy', 'name role');

    return res.status(200).json({ case: updatedCase });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  getCases,
  getCaseById,
  createCase,
  updateCase,
  addNote,
  linkEvidence,
};
