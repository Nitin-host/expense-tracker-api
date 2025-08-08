// routes/ExpenseRoutes.js
const express = require('express');
const router = express.Router();
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const expenseController = require('../controller/ExpenseController');
const multer = require('multer');
const upload = multer({ dest: 'tmp/' }); // temp local storage

// All routes require authentication
router.use(authenticateToken);

// Create new expense (with initial payment); support UPI screenshot
router.post(
    '/',
    upload.array('upiScreenshots', 5),
    asyncHandler(expenseController.createExpense)
);

// Add a payment to existing expense
router.post(
    '/:expenseId/add-payment',
    upload.array('upiScreenshots', 5),
    asyncHandler(expenseController.addPayment)
);

// Get all expenses for a solution card
router.get(
    '/solution-card/:solutionCardId',
    asyncHandler(expenseController.getExpensesBySolutionCard)
);

// Update expense (basic info, not payments)
router.put(
    '/:id',
    upload.array('upiScreenshots', 5),
    asyncHandler(expenseController.updateExpense)
);

// Delete expense (with screenshot cleanup)
router.delete(
    '/:id',
    asyncHandler(expenseController.deleteExpense)
);

// Get deleted expenses by solution card
router.get(
    '/solution-card/:solutionCardId/deleted',
    asyncHandler(expenseController.getDeletedExpensesBySolutionCard)
);

// Restore deleted expense
router.put(
    '/:id/restore',
    asyncHandler(expenseController.restoreExpense)
);

module.exports = router;
