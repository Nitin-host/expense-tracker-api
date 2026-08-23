// routes/ExpenseRoutes.js
const express = require('express');
const router = express.Router();
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const expenseController = require('../controller/ExpenseController');
const multer = require('multer');

const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);

const upload = multer({
    dest: 'tmp/',
    limits: { fileSize: 2 * 1024 * 1024, files: 5 },
    fileFilter: (req, file, cb) => {
        if (ALLOWED_MIME.has(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only JPEG, PNG, WebP, or GIF images are allowed.'));
        }
    },
});

router.use(authenticateToken);

router.post(
    '/',
    upload.array('upiScreenshots', 5),
    asyncHandler(expenseController.createExpense)
);

router.post(
    '/:expenseId/add-payment',
    upload.array('upiScreenshots', 5),
    asyncHandler(expenseController.addPayment)
);

router.get(
    '/solution-card/:solutionCardId',
    asyncHandler(expenseController.getExpensesBySolutionCard)
);

router.get(
    '/solution-card/:solutionCardId/deleted',
    asyncHandler(expenseController.getDeletedExpensesBySolutionCard)
);

router.get('/:id', asyncHandler(expenseController.getExpenseById));

router.put(
    '/:id',
    upload.array('upiScreenshots', 5),
    asyncHandler(expenseController.updateExpense)
);

router.delete('/:id', asyncHandler(expenseController.deleteExpense));

router.put('/:id/restore', asyncHandler(expenseController.restoreExpense));

module.exports = router;
