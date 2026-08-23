const express = require('express');
const router = express.Router({ mergeParams: true });
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const recurringController = require('../controller/RecurringExpenseController');

router.use(authenticateToken);

router.get('/', asyncHandler(recurringController.listRecurring));
router.post('/', asyncHandler(recurringController.createRecurring));
router.post('/process-due', asyncHandler(recurringController.processDueRecurring));
router.put('/:id', asyncHandler(recurringController.updateRecurring));
router.delete('/:id', asyncHandler(recurringController.deleteRecurring));

module.exports = router;
