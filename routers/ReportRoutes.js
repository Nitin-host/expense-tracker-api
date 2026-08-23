const express = require('express');
const router = express.Router();
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const reportController = require('../controller/ReportController');

router.use(authenticateToken);

router.get('/:solutionCardId/export', asyncHandler(reportController.exportData));
router.get('/:solutionCardId', asyncHandler(reportController.getReports));

module.exports = router;
