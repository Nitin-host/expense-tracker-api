const express = require('express');
const router = express.Router();
const authenticateToken = require('../middlewares/AuthenticateToken');
const authorizeRole = require('../middlewares/AuthorizeRole');
const asyncHandler = require('../middlewares/AsyncHandler');
const solutionCardController = require('../controller/SolutionCardController');

// All routes require authentication
router.use(authenticateToken);

// Create solution card
router.post('/', asyncHandler(solutionCardController.createSolutionCard));

// Get all solution cards accessible by the user (excluding soft-deleted)
router.get('/', asyncHandler(solutionCardController.getSolutionCards));

// Get all soft-deleted solution cards owned by the user
router.get('/deleted', authenticateToken, authorizeRole(['super_admin']), asyncHandler(solutionCardController.getDeletedSolutionCards));

// Get solution card by ID (only if not deleted)
router.get('/:id', asyncHandler(solutionCardController.getSolutionCardById));

// Update solution card by ID (owner-only should be enforced inside controller)
router.put('/:id', asyncHandler(solutionCardController.updateSolutionCard));

// Soft delete solution card by ID (owner-only)
router.delete('/:id', authenticateToken, authorizeRole(['admin', 'super_admin']), asyncHandler(solutionCardController.deleteSolutionCard));

// Restore a soft-deleted solution card by ID (owner-only)
router.put('/:id/restore', asyncHandler(solutionCardController.restoreSolutionCard));

router.post(
    '/:id/share',
    asyncHandler(solutionCardController.shareSolutionCard)
);

module.exports = router;
