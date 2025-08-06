const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const CollectedCash = require('../models/CollectedCash');
const Expense = require('../models/Expense');
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');

router.use(authenticateToken);

router.get('/dashboard/:solutionCardId', asyncHandler(async (req, res) => {
    const { solutionCardId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(solutionCardId)) {
        return res.status(400).json({ message: "Invalid solutionCardId" });
    }

    const solutionObjectId = new mongoose.Types.ObjectId(solutionCardId);

    // Aggregate total collected cash
    const collectedCashAgg = await CollectedCash.aggregate([
        { $match: { solutionCardId: solutionObjectId } },
        { $group: { _id: null, totalCollectedCash: { $sum: '$amount' } } }
    ]);
    const totalCollectedCash = collectedCashAgg.length > 0 ? collectedCashAgg[0].totalCollectedCash : 0;

    // Aggregate total expenses
    const expenseAgg = await Expense.aggregate([
        { $match: { solutionCard: solutionObjectId } },
        { $group: { _id: null, totalExpenses: { $sum: '$amount' } } }
    ]);
    const totalExpenses = expenseAgg.length > 0 ? expenseAgg[0].totalExpenses : 0;

    const remainingBudget = totalCollectedCash - totalExpenses;
    const percentageSpent = totalCollectedCash > 0 ? Math.round((totalExpenses / totalCollectedCash) * 100) : 0;

    // Get recent 5 expenses sorted by createdAt descending
    const recentExpenses = await Expense.find({ solutionCard: solutionObjectId })
        .sort({ createdAt: -1 })
        .limit(5)
        .select('name amount createdAt')
        .lean();

    // Get recent 5 collected cash entries sorted by collectedDate descending
    const recentCollectedCash = await CollectedCash.find({ solutionCardId: solutionObjectId })
        .sort({ collectedDate: -1 })
        .limit(5)
        .select('amount name collectedDate')
        .lean();

    res.json({
        solutionCardId,
        totalCollectedCash,
        totalExpenses,
        remainingBudget,
        percentageSpent,
        recentExpenses: recentExpenses.map(({ _id, name, amount, createdAt }) => ({
            id: _id,
            name,
            amount,
            date: createdAt,
        })),
        recentCollectedCash: recentCollectedCash.map(({ _id, name, amount, collectedDate }) => ({
            id: _id,
            name,
            amount,
            date: collectedDate,
        })),
    });
}));

module.exports = router;
