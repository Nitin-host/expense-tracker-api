const express = require('express');
const router = express.Router({ mergeParams: true });
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const budgetController = require('../controller/BudgetController');

router.use(authenticateToken);

router.get('/', asyncHandler(budgetController.listBudgets));
router.post('/', asyncHandler(budgetController.createBudget));
router.put('/:id', asyncHandler(budgetController.updateBudget));
router.delete('/:id', asyncHandler(budgetController.deleteBudget));

module.exports = router;
