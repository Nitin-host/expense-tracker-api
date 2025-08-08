const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const CollectedCash = require('../models/CollectedCash');
const Expense = require('../models/Expense');
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');

router.use(authenticateToken);

router.get(
    '/dashboard/:solutionCardId',
    asyncHandler(async (req, res) => {
        const { solutionCardId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(solutionCardId)) {
            return res.status(400).json({ message: 'Invalid solutionCardId' });
        }

        const solutionObjectId = new mongoose.Types.ObjectId(solutionCardId);

        // Run all queries in parallel
        const [
            collectedCashAgg,
            expenseAgg,
            expenseByCategoryAgg,
            collectedCashByCategoryAgg,
            recentExpenses,
            recentCollectedCash,
        ] = await Promise.all([
            // total collected cash
            CollectedCash.aggregate([
                { $match: { solutionCardId: solutionObjectId } },
                {
                    $group: {
                        _id: null,
                        totalCollectedCash: { $sum: '$amount' },
                    },
                },
            ]),

            // total expenses
            Expense.aggregate([
                { $match: { solutionCard: solutionObjectId } },
                {
                    $group: {
                        _id: null,
                        totalExpenses: { $sum: '$amount' },
                    },
                },
            ]),

            // expense summary by category
            Expense.aggregate([
                { $match: { solutionCard: solutionObjectId } },
                {
                    $group: {
                        _id: { $ifNull: ['$category', 'Uncategorized'] },
                        amount: { $sum: '$amount' },
                    },
                },
                {
                    $project: {
                        category: '$_id',
                        amount: 1,
                        _id: 0,
                    },
                },
            ]),

            // collected cash summary by name/category
            CollectedCash.aggregate([
                { $match: { solutionCardId: solutionObjectId } },
                {
                    $group: {
                        _id: { $ifNull: ['$name', 'Uncategorized'] },
                        amount: { $sum: '$amount' },
                    },
                },
                {
                    $project: {
                        category: '$_id',
                        amount: 1,
                        _id: 0,
                    },
                },
            ]),

            // recent 5 expenses
            Expense.find({ solutionCard: solutionObjectId })
                .sort({ createdAt: -1 })
                .limit(5)
                .select('name amount createdAt category')
                .lean(),

            // recent 5 collected cash
            CollectedCash.find({ solutionCardId: solutionObjectId })
                .sort({ collectedDate: -1 })
                .limit(5)
                .select('amount name collectedDate')
                .lean(),
        ]);

        const totalCollectedCash =
            collectedCashAgg.length > 0 ? collectedCashAgg[0].totalCollectedCash : 0;
        const totalExpenses = expenseAgg.length > 0 ? expenseAgg[0].totalExpenses : 0;

        const remainingBudget = totalCollectedCash - totalExpenses;
        const percentageSpent =
            totalCollectedCash > 0 ? Math.round((totalExpenses / totalCollectedCash) * 100) : 0;

        return res.json({
            solutionCardId,
            totalCollectedCash,
            totalExpenses,
            remainingBudget,
            percentageSpent,

            expenseSummary: {
                total: totalExpenses,
                byCategory: expenseByCategoryAgg,
            },
            collectedCashSummary: {
                total: totalCollectedCash,
                byCategory: collectedCashByCategoryAgg,
            },

            recentExpenses: recentExpenses.map(({ _id, name, amount, createdAt, category }) => ({
                id: _id,
                name,
                amount,
                date: createdAt,
                category,
            })),
            recentCollectedCash: recentCollectedCash.map(({ _id, name, amount, collectedDate }) => ({
                id: _id,
                name,
                amount,
                date: collectedDate,
            })),
        });
    })
);

module.exports = router;
