const express = require('express');
const router = express.Router();
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const checkSolutionCardAccess = require('../middlewares/CheckSolutionCardAccess');
const expenseController = require('../controller/ExpenseController');
const multer = require('multer');
const upload = multer({ dest: 'tmp/' }); // temp local storage

const Expense = require('../models/Expense');
const SolutionCard = require('../models/SolutionCard');

// All routes require authentication
router.use(authenticateToken);

// Create new expense (with initial payment); support UPI screenshot
router.post(
    '/',
    upload.array('upiScreenshots', 5),
    checkSolutionCardAccess,
    asyncHandler((req, res, next) => {
        if (!['owner', 'editor'].includes(req.solutionCardRole)) {
            return res.status(403).json({ message: 'Permission denied to add expense.' });
        }
        expenseController.createExpense(req, res, next);
    })
);

// Add a payment to existing expense (advance/final settlement); support UPI screenshot
router.post(
    '/:expenseId/add-payment',
    upload.array('upiScreenshots', 5),
    asyncHandler(async (req, res, next) => {
        const expense = await Expense.findById(req.params.expenseId);
        if (!expense) return res.status(404).json({ message: 'Expense not found' });

        req.body.solutionCard = expense.solutionCard; // pass to middleware

        checkSolutionCardAccess(req, res, () => {
            if (!['owner', 'editor'].includes(req.solutionCardRole)) {
                return res.status(403).json({ message: 'Permission denied to add payments.' });
            }
            expenseController.addPayment(req, res, next);
        });
    })
);

// Get all expenses for a solution card (owner/editor/viewer)
router.get(
    '/solution-card/:solutionCardId',
    checkSolutionCardAccess,
    asyncHandler((req, res, next) => {
        if (!['owner', 'editor', 'viewer'].includes(req.solutionCardRole)) {
            return res.status(403).json({ message: 'Access denied.' });
        }
        expenseController.getExpensesBySolutionCard(req, res, next);
    })
);

// Update expense (basic info, not payments) owner/editor only
router.put(
    '/:id',
    upload.array('upiScreenshots', 5),
    checkSolutionCardAccess,
    asyncHandler((req, res, next) => {
        if (!['owner', 'editor'].includes(req.solutionCardRole)) {
            return res.status(403).json({ message: 'Permission denied to update expense.' });
        }
        expenseController.updateExpense(req, res, next);
    })
);

// Delete expense (with screenshot cleanup) owner/editor or paidBy user
router.delete(
    '/:id',
    asyncHandler(async (req, res, next) => {
        const expense = await Expense.findById(req.params.id);
        if (!expense) return res.status(404).json({ message: 'Expense not found' });

        const solutionCard = await SolutionCard.findById(expense.solutionCard);
        if (!solutionCard) return res.status(404).json({ message: 'Solution card not found' });

        const userId = req.user.userId;
        let role = null;
        if (solutionCard.owner.equals(userId)) {
            role = 'owner';
        } else {
            const sharedUser = solutionCard.sharedWith.find(su => su.user.equals(userId));
            if (sharedUser) role = sharedUser.role;
        }

        if (!(role === 'owner' || role === 'editor' || expense.paidBy.equals(userId))) {
            return res.status(403).json({ message: 'Permission denied to delete expense.' });
        }

        expenseController.deleteExpense(req, res, next);
    })
);

// Get deleted expenses by solution card (owner only)
router.get(
    '/solution-card/:solutionCardId/deleted',
    checkSolutionCardAccess,
    asyncHandler((req, res, next) => {
        if (req.solutionCardRole !== 'owner') {
            return res.status(403).json({ message: 'Only owner can view deleted expenses.' });
        }
        expenseController.getDeletedExpensesBySolutionCard(req, res, next);
    })
);

// Restore deleted expense (owner only)
router.put(
    '/:id/restore',
    asyncHandler(async (req, res, next) => {
        const expense = await Expense.findById(req.params.id);
        if (!expense) return res.status(404).json({ message: 'Expense not found' });

        const solutionCard = await SolutionCard.findById(expense.solutionCard);
        if (!solutionCard) return res.status(404).json({ message: 'Solution card not found' });

        if (!solutionCard.owner.equals(req.user.userId)) {
            return res.status(403).json({ message: 'Only owner can restore this expense.' });
        }
        expenseController.restoreExpense(req, res, next);
    })
);

module.exports = router;
