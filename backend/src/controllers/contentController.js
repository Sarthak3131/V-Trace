'use strict';

const mongoose = require('mongoose');
const Content = require('../models/Content');
const Case = require('../models/Case');
const { verifyAccessToken } = require('../utils/jwt');
const { buildMerkleRoot } = require('../core/merkle');
const { forensicQueue } = require('../utils/forensicQueue');
const { logEvent } = require('../utils/auditLogger');
const AIAnalysisResult = require('../models/AIAnalysisResult');
const { broadcast } = require('../utils/websocket');
const { getUploadParams } = require('../utils/storage');
const env = require('../config/env');

const MOD_ROLES = ['admin', 'moderator'];
const ALLOWED_STATUS = ['pending', 'verified', 'flagged', 'rejected'];

function isPrivileged(role) {
  return role === 'admin' || role === 'moderator';
}

function sanitizeStatus(status) {
  if (!status) return null;
  const clean = String(status).trim().toLowerCase();
  return ALLOWED_STATUS.includes(clean) ? clean : null;
}

function parsePagination(query) {
  const page = Math.max(parseInt(query.page, 10) || 1, 1);
  const requestedLimit = parseInt(query.limit, 10) || 10;
  const limit = Math.min(Math.max(requestedLimit, 1), 50);
  const skip = (page - 1) * limit;

  return { page, limit, skip };
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildCommonQueryFilters(query) {
  const filters = {};

  if (query.contentType) {
    const cleanContentType = String(query.contentType).trim().toLowerCase();
    const ALLOWED_CONTENT_TYPES = ['text', 'image', 'document', 'video', 'audio'];
    if (ALLOWED_CONTENT_TYPES.includes(cleanContentType)) {
      filters.contentType = cleanContentType;
    }
  }

  if (query.search) {
    const searchTerm = String(query.search).trim();
    if (/^[0-9a-fA-F]{64}$/.test(searchTerm)) {
      filters.originalHash = searchTerm.toLowerCase();
    } else {
      const pattern = new RegExp(escapeRegex(searchTerm), 'i');
      filters.$or = [{ title: pattern }, { description: pattern }];
    }
  }

  if (query.tags) {
    const tags = String(query.tags)
      .split(',')
      .map((tag) => tag.trim().toLowerCase())
      .filter(Boolean);

    if (tags.length > 0) {
      filters.tags = { $in: tags };
    }
  }

  return filters;
}

function getSort(sortBy) {
  return sortBy === 'oldest' ? { createdAt: 1 } : { createdAt: -1 };
}

function getOptionalAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  try {
    const decoded = verifyAccessToken(authHeader.split(' ')[1]);
    return { userId: decoded.userId, role: decoded.role };
  } catch (error) {
    return null;
  }
}

function createPagination(page, limit, total) {
  return {
    page,
    limit,
    total,
    pages: Math.ceil(total / limit) || 1,
  };
}

function calculateTrustScores(status, derivationType, parentContent) {
  let authenticityScore = 50; // default for pending
  if (status === 'verified') authenticityScore = 100;
  else if (status === 'flagged' || status === 'rejected') authenticityScore = 0;

  let metadataRiskScore = 0;
  const type = derivationType || 'original';
  if (type === 'edit') metadataRiskScore = 15;
  else if (type === 'ai-modification') metadataRiskScore = 75;
  else if (type === 'splice') metadataRiskScore = 40;

  let parentProvenance = parentContent ? (parentContent.provenanceScore ?? 100) : 100;
  let provenancePenalty = 0;
  if (type === 'copy') provenancePenalty = 10;
  else if (type === 'edit') provenancePenalty = 15;
  else if (type === 'ai-modification') provenancePenalty = 30;
  else if (type === 'splice') provenancePenalty = 20;

  const provenanceScore = Math.max(0, parentProvenance - provenancePenalty);
  const integrityVerificationScore = Math.round((authenticityScore * 0.4) + (provenanceScore * 0.4) + ((100 - metadataRiskScore) * 0.2));
  const verificationConfidence = Math.max(0, 95 - Math.round(metadataRiskScore * 0.15));

  return {
    authenticityScore,
    provenanceScore,
    metadataRiskScore,
    integrityVerificationScore,
    verificationConfidence
  };
}

async function createContent(req, res, next) {
  try {
    const {
      title,
      description,
      contentType,
      originalHash,
      merkleRoot,
      chunkHashes,
      fileSize,
      mimeType,
      tags,
      isPublic,
      metadata,
      parentId,
      derivationType,
    } = req.body;

    const normalizedOriginalHash = String(originalHash).trim().toLowerCase();

    const duplicate = await Content.findOne({
      owner: req.user.userId,
      originalHash: normalizedOriginalHash,
    });

    if (duplicate) {
      return res.status(409).json({ error: 'Content with this hash already registered' });
    }

    // Cryptographic validation
    let validatedChunkHashes = Array.isArray(chunkHashes) && chunkHashes.length > 0
      ? chunkHashes.map(h => String(h).trim().toLowerCase())
      : [normalizedOriginalHash];

    let calculatedMerkleRoot;
    try {
      calculatedMerkleRoot = buildMerkleRoot(validatedChunkHashes);
    } catch (err) {
      return res.status(400).json({
        error: `Cryptographic validation failed: ${err.message}`,
      });
    }

    if (merkleRoot && String(merkleRoot).trim().toLowerCase() !== calculatedMerkleRoot) {
      return res.status(400).json({
        error: `Cryptographic validation failed: provided merkleRoot does not match calculated root. Expected: ${calculatedMerkleRoot}`,
      });
    }

    // Resolve parent content and compute scores
    let parentContent = null;
    if (parentId) {
      if (!mongoose.Types.ObjectId.isValid(parentId)) {
        return res.status(400).json({ error: 'Invalid parentId format' });
      }
      parentContent = await Content.findById(parentId);
      if (!parentContent) {
        return res.status(404).json({ error: 'Parent content not found' });
      }
    }

    const scores = calculateTrustScores('pending', derivationType, parentContent);

    const content = await Content.create({
      title,
      description,
      contentType,
      originalHash: normalizedOriginalHash,
      merkleRoot: calculatedMerkleRoot,
      chunkHashes: validatedChunkHashes,
      fileSize,
      mimeType,
      tags,
      isPublic,
      metadata,
      owner: req.user.userId,
      parentId: parentId || null,
      derivationType: derivationType || 'original',
      authenticityScore: scores.authenticityScore,
      provenanceScore: scores.provenanceScore,
      metadataRiskScore: scores.metadataRiskScore,
      integrityVerificationScore: scores.integrityVerificationScore,
      verificationConfidence: scores.verificationConfidence,
    });

    // Trigger forensic analysis background worker
    await forensicQueue.add(content._id.toString());

    // Cryptographically log the content registration action
    await logEvent({
      action: 'content-registered',
      entityType: 'Content',
      entityId: content._id,
      performedBy: req.user.userId,
      details: { title: content.title, originalHash: content.originalHash }
    });

    broadcast('new-evidence', content);

    return res.status(201).json({ content });
  } catch (error) {
    return next(error);
  }
}

async function getAllContent(req, res, next) {
  try {
    const { page, limit, skip } = parsePagination(req.query);
    const authUser = getOptionalAuth(req);

    const filters = {
      ...buildCommonQueryFilters(req.query),
    };

    const isUserPrivileged = authUser && isPrivileged(authUser.role);
    if (!isUserPrivileged) {
      filters.isPublic = true;
    } else if (req.query.isPublic !== undefined) {
      filters.isPublic = req.query.isPublic === 'true';
    }

    const cleanStatus = sanitizeStatus(req.query.status);
    if (cleanStatus && authUser && isPrivileged(authUser.role)) {
      filters.status = cleanStatus;
    }

    const [contents, total] = await Promise.all([
      Content.find(filters)
        .populate('owner', 'name')
        .sort(getSort(req.query.sortBy))
        .skip(skip)
        .limit(limit),
      Content.countDocuments(filters),
    ]);

    return res.status(200).json({
      contents,
      pagination: createPagination(page, limit, total),
    });
  } catch (error) {
    return next(error);
  }
}

async function getMyContent(req, res, next) {
  try {
    const { page, limit, skip } = parsePagination(req.query);

    const filters = {
      ...buildCommonQueryFilters(req.query),
      owner: req.user.userId,
    };

    const cleanStatus = sanitizeStatus(req.query.status);
    if (cleanStatus) {
      filters.status = cleanStatus;
    }

    const [contents, total] = await Promise.all([
      Content.find(filters)
        .populate('owner', 'name')
        .populate('verifiedBy', 'name')
        .sort(getSort(req.query.sortBy))
        .skip(skip)
        .limit(limit),
      Content.countDocuments(filters),
    ]);

    return res.status(200).json({
      contents,
      pagination: createPagination(page, limit, total),
    });
  } catch (error) {
    return next(error);
  }
}

async function getContentById(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const content = await Content.findById(req.params.id)
      .populate('owner', 'name')
      .populate('verifiedBy', 'name');

    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    if (!content.isPublic) {
      const authUser = getOptionalAuth(req) || req.user;
      const isOwner = authUser && authUser.userId && String(content.owner._id) === String(authUser.userId);
      const isMod = authUser && isPrivileged(authUser.role);

      if (!isOwner && !isMod) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    return res.status(200).json({ content });
  } catch (error) {
    return next(error);
  }
}

async function updateContent(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const content = await Content.findById(req.params.id);
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const isOwner = String(content.owner) === String(req.user.userId);
    const isMod = isPrivileged(req.user.role);

    if (!isOwner && !isMod) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const ownerAllowed = ['title', 'description', 'tags', 'isPublic', 'metadata'];
    const adminAllowed = ['status', 'verifiedBy', 'verifiedAt'];

    const nextFields = {};
    for (const field of ownerAllowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, field)) {
        nextFields[field] = req.body[field];
      }
    }

    if (isMod) {
      for (const field of adminAllowed) {
        if (Object.prototype.hasOwnProperty.call(req.body, field)) {
          nextFields[field] = req.body[field];
        }
      }
    }

    if (nextFields.status) {
      const cleanStatus = sanitizeStatus(nextFields.status);
      if (cleanStatus) {
        nextFields.status = cleanStatus;
        if (cleanStatus === 'verified') {
          nextFields.verifiedAt = new Date();
          nextFields.verifiedBy = req.user.userId;
        }

        // Recalculate scores
        const parentContent = content.parentId ? await Content.findById(content.parentId) : null;
        const scores = calculateTrustScores(cleanStatus, content.derivationType, parentContent);
        Object.assign(nextFields, scores);
      }
    }

    let action = 'content-updated';
    if (nextFields.status) {
      if (nextFields.status === 'verified') action = 'content-verified';
      else if (nextFields.status === 'flagged') action = 'content-flagged';
      else if (nextFields.status === 'rejected') action = 'content-rejected';
    }

    Object.assign(content, nextFields);
    await content.save();

    // Log Chain of Custody event
    await logEvent({
      action,
      entityType: 'Content',
      entityId: content._id,
      performedBy: req.user.userId,
      details: nextFields
    });

    const updatedContent = await Content.findById(content._id)
      .populate('owner', 'name')
      .populate('verifiedBy', 'name');

    return res.status(200).json({ content: updatedContent });
  } catch (error) {
    return next(error);
  }
}

async function deleteContent(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const content = await Content.findById(req.params.id);
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const isOwner = String(content.owner) === String(req.user.userId);
    const isAdmin = req.user.role === 'admin';

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Log Chain of Custody event before deletion
    await logEvent({
      action: 'content-deleted',
      entityType: 'Content',
      entityId: content._id,
      performedBy: req.user.userId,
      details: { title: content.title, originalHash: content.originalHash }
    });

    await content.deleteOne();

    return res.status(200).json({ message: 'Content deleted' });
  } catch (error) {
    return next(error);
  }
}

async function verifyContent(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const content = await Content.findById(req.params.id);
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    content.status = 'verified';
    content.verifiedAt = new Date();
    content.verifiedBy = req.user.userId;

    const parentContent = content.parentId ? await Content.findById(content.parentId) : null;
    const scores = calculateTrustScores('verified', content.derivationType, parentContent);
    Object.assign(content, scores);

    await content.save();

    // Log Chain of Custody event
    await logEvent({
      action: 'content-verified',
      entityType: 'Content',
      entityId: content._id,
      performedBy: req.user.userId,
      details: { status: 'verified', verifiedAt: content.verifiedAt }
    });

    const updatedContent = await Content.findById(content._id)
      .populate('owner', 'name')
      .populate('verifiedBy', 'name');

    return res.status(200).json({ content: updatedContent });
  } catch (error) {
    return next(error);
  }
}

async function flagContent(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const content = await Content.findById(req.params.id);
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    content.status = 'flagged';

    const parentContent = content.parentId ? await Content.findById(content.parentId) : null;
    const scores = calculateTrustScores('flagged', content.derivationType, parentContent);
    Object.assign(content, scores);

    if (req.body && typeof req.body.reason === 'string' && req.body.reason.trim() !== '') {
      const metadata = content.metadata && typeof content.metadata === 'object' ? content.metadata : {};
      metadata.flagReason = req.body.reason.trim();
      content.metadata = metadata;
    }

    await content.save();

    // Log Chain of Custody event
    await logEvent({
      action: 'content-flagged',
      entityType: 'Content',
      entityId: content._id,
      performedBy: req.user.userId,
      details: { status: 'flagged', flagReason: content.metadata ? content.metadata.flagReason : undefined }
    });

    const updatedContent = await Content.findById(content._id)
      .populate('owner', 'name')
      .populate('verifiedBy', 'name');

    return res.status(200).json({ content: updatedContent });
  } catch (error) {
    return next(error);
  }
}

async function checkDuplicate(req, res, next) {
  try {
    const { originalHash } = req.body;

    if (!originalHash || String(originalHash).trim() === '') {
      return res.status(400).json({ error: 'originalHash is required' });
    }

    const normalizedOriginalHash = String(originalHash).trim().toLowerCase();

    const matches = await Content.find({ originalHash: normalizedOriginalHash })
      .populate('owner', 'name')
      .select('title owner createdAt')
      .sort({ createdAt: -1 });

    return res.status(200).json({
      isDuplicate: matches.length > 0,
      matches: matches.map((item) => ({
        id: item._id,
        title: item.title,
        owner: item.owner,
        createdAt: item.createdAt,
      })),
    });
  } catch (error) {
    return next(error);
  }
}

function getLinkWeight(type) {
  switch (type) {
    case 'copy': return 0.95;
    case 'edit': return 0.80;
    case 'splice': return 0.50;
    case 'ai-modification': return 0.25;
    default: return 1.0;
  }
}

async function getBaseConfidence(item) {
  if (item.status === 'verified') return 100;
  if (item.status === 'flagged' || item.status === 'rejected') return 90;

  const analysis = await AIAnalysisResult.findOne({ contentId: item._id });
  if (analysis) {
    if (analysis.status === 'completed') return 80;
    if (analysis.status === 'failed') return 40;
    return 60;
  }
  return 50;
}

async function getProvenanceGraph(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const target = await Content.findById(req.params.id).populate('owner', 'name');
    if (!target) {
      return res.status(404).json({ error: 'Content not found' });
    }

    // Bounded traversal up (ancestors)
    const ancestors = [];
    let current = target;
    let depth = 0;
    while (current.parentId && depth < 10) {
      const parent = await Content.findById(current.parentId).populate('owner', 'name');
      if (!parent) break;
      ancestors.unshift(parent);
      current = parent;
      depth++;
    }
    const orderedPath = [...ancestors, target];

    // Traversal down (direct children)
    const descendants = await Content.find({ parentId: target._id }).populate('owner', 'name');

    // Perform score propagation
    const scoreMap = new Map();

    for (let i = 0; i < orderedPath.length; i++) {
      const item = orderedPath[i];
      const itemIdStr = item._id.toString();

      let provenance = item.provenanceScore ?? 100;
      const baseConf = await getBaseConfidence(item);
      let confidence = baseConf;

      if (i > 0) {
        const parent = orderedPath[i - 1];
        const parentScores = scoreMap.get(parent._id.toString());
        const linkType = item.derivationType || 'edit';
        const weight = getLinkWeight(linkType);

        provenance = Math.round(parentScores.provenance * weight);
        confidence = Math.round((parentScores.confidence * baseConf) / 100);
      }

      const trust = Math.round(
        ((item.authenticityScore * 0.4) + (provenance * 0.4) + ((100 - item.metadataRiskScore) * 0.2)) *
        (confidence / 100)
      );

      scoreMap.set(itemIdStr, { provenance, confidence, trust });
    }

    for (const child of descendants) {
      const childIdStr = child._id.toString();
      const parentScores = scoreMap.get(target._id.toString());
      const linkType = child.derivationType || 'edit';
      const weight = getLinkWeight(linkType);

      const provenance = Math.round(parentScores.provenance * weight);
      const baseConf = await getBaseConfidence(child);
      const confidence = Math.round((parentScores.confidence * baseConf) / 100);
      const trust = Math.round(
        ((child.authenticityScore * 0.4) + (provenance * 0.4) + ((100 - child.metadataRiskScore) * 0.2)) *
        (confidence / 100)
      );

      scoreMap.set(childIdStr, { provenance, confidence, trust });
    }

    // Construct returned nodes decorated with propagated scores and cases
    const nodes = [];
    const nodeMap = new Set();
    const allNodes = [...orderedPath, ...descendants];

    for (const item of allNodes) {
      const idStr = item._id.toString();
      if (!nodeMap.has(idStr)) {
        nodeMap.add(idStr);

        const activeCases = await Case.find({ evidence: item._id }).select('title status severity');
        const calculated = scoreMap.get(idStr);

        nodes.push({
          id: idStr,
          title: item.title,
          contentType: item.contentType,
          originalHash: item.originalHash,
          status: item.status,
          owner: item.owner?.name || 'Unknown',
          derivationType: item.derivationType || 'original',
          scores: {
            authenticity: item.authenticityScore ?? 100,
            provenance: calculated.provenance,
            metadataRiskScore: item.metadataRiskScore ?? 0,
            trust: calculated.trust,
            confidence: calculated.confidence,
          },
          activeCases: activeCases.map((c) => ({
            _id: c._id,
            title: c.title,
            status: c.status,
            severity: c.severity,
          })),
        });
      }
    }

    // Construct returned links decorated with weights
    const links = [];

    // Ancestor links
    for (let i = 1; i < orderedPath.length; i++) {
      const source = orderedPath[i - 1]._id.toString();
      const targetNode = orderedPath[i]._id.toString();
      const type = orderedPath[i].derivationType || 'edit';
      const weight = getLinkWeight(type);

      links.push({
        source,
        target: targetNode,
        type,
        weight,
      });
    }

    // Descendant links
    for (const child of descendants) {
      const source = target._id.toString();
      const targetNode = child._id.toString();
      const type = child.derivationType || 'edit';
      const weight = getLinkWeight(type);

      links.push({
        source,
        target: targetNode,
        type,
        weight,
      });
    }

    return res.status(200).json({ nodes, links });
  } catch (error) {
    return next(error);
  }
}

async function getContentAnalysis(req, res, next) {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    const content = await Content.findById(req.params.id);
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    if (!content.isPublic) {
      const authUser = getOptionalAuth(req) || req.user;
      const isOwner = authUser && authUser.userId && String(content.owner) === String(authUser.userId);
      const isMod = authUser && isPrivileged(authUser.role);

      if (!isOwner && !isMod) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    let analysis = await AIAnalysisResult.findOne({ contentId: req.params.id });
    if (!analysis) {
      await forensicQueue.add(req.params.id);
      analysis = await AIAnalysisResult.findOne({ contentId: req.params.id });
    }

    return res.status(200).json({ analysis });
  } catch (error) {
    return next(error);
  }
}

async function getUploadParameters(req, res, next) {
  try {
    const { fileName, fileType } = req.body;
    if (!fileName || !fileType) {
      return res.status(400).json({ error: 'fileName and fileType are required' });
    }

    const params = await getUploadParams(fileName, fileType);
    return res.status(200).json(params);
  } catch (error) {
    return next(error);
  }
}

async function uploadLocalFile(req, res, next) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const downloadUrl = `${env.API_URL}/uploads/${req.file.filename}`;
    return res.status(200).json({
      message: 'File uploaded successfully',
      downloadUrl,
      key: req.file.filename
    });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  createContent,
  getAllContent,
  getMyContent,
  getContentById,
  updateContent,
  deleteContent,
  verifyContent,
  flagContent,
  checkDuplicate,
  getProvenanceGraph,
  getContentAnalysis,
  getUploadParameters,
  uploadLocalFile,
};
