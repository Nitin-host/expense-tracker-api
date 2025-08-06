const express = require('express');
const router = express.Router();
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const collectedCashController = require('../controller/CollectedCashController');

// Require auth for all collected cash routes
router.use(authenticateToken);

router.post(
    '/',
    asyncHandler(collectedCashController.createCollectedCash)
);

router.get(
    '/solution/:solutionCardId',
    asyncHandler(collectedCashController.getCollectedCashBySolution)
);

router.put(
    '/:id',
    asyncHandler(collectedCashController.updateCollectedCash)
);

router.delete(
    '/:id',
    asyncHandler(collectedCashController.deleteCollectedCash)
);

module.exports = router;
