const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const CollectedCash = require('../models/CollectedCash');
const Expense = require('../models/Expense');
const authenticateToken = require('../middlewares/AuthenticateToken');
const asyncHandler = require('../middlewares/AsyncHandler');
const { checkPermission } = require('../utils/checkPermission');
const { BadRequestError } = require('../utils/Errors');

router.use(authenticateToken);

router.get(
    '/dashboard/:solutionCardId',
    asyncHandler(async (req, res) => {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;

        if (!mongoose.Types.ObjectId.isValid(solutionCardId)) {
            throw new BadRequestError('Invalid solutionCardId');
        }

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true,
        });

        const solutionObjectId = new mongoose.Types.ObjectId(solutionCardId);
        const expenseMatch = { solutionCard: solutionObjectId, isDeleted: { $ne: true } };
        const cashMatch = { solutionCardId: solutionObjectId };

        const [expenseFacetResult, collectedFacetResult, recentExpenses, recentCollectedCash] =
            await Promise.all([
                Expense.aggregate([
                    { $match: expenseMatch },
                    {
                        $facet: {
                            total: [
                                {
                                    $group: {
                                        _id: null,
                                        totalExpenses: { $sum: '$amount' },
                                    },
                                },
                            ],
                            byCategory: [
                                {
                                    $group: {
                                        _id: { $ifNull: ['$category', 'Uncategorized'] },
                                        amount: { $sum: '$amount' },
                                    },
                                },
                                { $project: { category: '$_id', amount: 1, _id: 0 } },
                            ],
                            byPaymentMethod: [
                                {
                                    $unwind: {
                                        path: '$payments',
                                        preserveNullAndEmptyArrays: false,
                                    },
                                },
                                {
                                    $group: {
                                        _id: {
                                            $ifNull: ['$payments.paymentMethod', 'unknown'],
                                        },
                                        amount: { $sum: '$payments.paidAmount' },
                                        count: { $sum: 1 },
                                    },
                                },
                            ],
                        },
                    },
                ]),
                CollectedCash.aggregate([
                    { $match: cashMatch },
                    {
                        $facet: {
                            total: [
                                {
                                    $group: {
                                        _id: null,
                                        totalCollectedCash: { $sum: '$amount' },
                                    },
                                },
                            ],
                            byCategory: [
                                {
                                    $group: {
                                        _id: { $ifNull: ['$name', 'Uncategorized'] },
                                        amount: { $sum: '$amount' },
                                    },
                                },
                                { $project: { category: '$_id', amount: 1, _id: 0 } },
                            ],
                            byMethod: [
                                {
                                    $group: {
                                        _id: { $ifNull: ['$paymentMethod', 'cash'] },
                                        amount: { $sum: '$amount' },
                                        count: { $sum: 1 },
                                    },
                                },
                            ],
                        },
                    },
                ]),
                Expense.find(expenseMatch)
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .select('name amount createdAt category')
                    .lean(),
                CollectedCash.find(cashMatch)
                    .sort({ collectedDate: -1 })
                    .limit(5)
                    .select('amount name collectedDate paymentMethod')
                    .lean(),
            ]);

        const expenseFacets = expenseFacetResult[0] || {
            total: [],
            byCategory: [],
            byPaymentMethod: [],
        };
        const collectedFacets = collectedFacetResult[0] || {
            total: [],
            byCategory: [],
            byMethod: [],
        };

        const totalCollectedCash = collectedFacets.total[0]?.totalCollectedCash || 0;
        const totalExpenses = expenseFacets.total[0]?.totalExpenses || 0;
        const remainingBudget = totalCollectedCash - totalExpenses;
        const percentageSpent =
            totalCollectedCash > 0 ? Math.round((totalExpenses / totalCollectedCash) * 100) : 0;

        const summarizeMethodAgg = (rows) => {
            const byMethod = { cash: 0, upi: 0 };
            let cashCount = 0;
            let upiCount = 0;
            for (const row of rows) {
                const method = String(row._id || 'cash').toLowerCase();
                const amount = Number(row.amount) || 0;
                const count = Number(row.count) || 0;
                if (method === 'upi') {
                    byMethod.upi = amount;
                    upiCount = count;
                } else {
                    byMethod.cash += amount;
                    cashCount += count;
                }
            }
            return {
                cash: byMethod.cash,
                upi: byMethod.upi,
                total: byMethod.cash + byMethod.upi,
                cashCount,
                upiCount,
            };
        };

        const expensePayments = summarizeMethodAgg(expenseFacets.byPaymentMethod);
        const collectedPayments = summarizeMethodAgg(collectedFacets.byMethod);

        return res.json({
            solutionCardId,
            totalCollectedCash,
            totalExpenses,
            remainingBudget,
            percentageSpent,
            paymentMethodSummary: {
                cash: expensePayments.cash,
                upi: expensePayments.upi,
                totalPaid: expensePayments.total,
                cashCount: expensePayments.cashCount,
                upiCount: expensePayments.upiCount,
            },
            collectedPaymentMethodSummary: {
                cash: collectedPayments.cash,
                upi: collectedPayments.upi,
                totalCollected: collectedPayments.total,
                cashCount: collectedPayments.cashCount,
                upiCount: collectedPayments.upiCount,
            },
            expenseSummary: {
                total: totalExpenses,
                byCategory: expenseFacets.byCategory,
            },
            collectedCashSummary: {
                total: totalCollectedCash,
                byCategory: collectedFacets.byCategory,
            },
            recentExpenses: recentExpenses.map(({ _id, name, amount, createdAt, category }) => ({
                id: _id,
                name,
                amount,
                date: createdAt,
                category,
            })),
            recentCollectedCash: recentCollectedCash.map(
                ({ _id, name, amount, collectedDate, paymentMethod }) => ({
                    id: _id,
                    name,
                    amount,
                    date: collectedDate,
                    paymentMethod: paymentMethod || 'cash',
                })
            ),
        });
    })
);

module.exports = router;
