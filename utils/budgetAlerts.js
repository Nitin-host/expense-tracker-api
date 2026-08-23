const Budget = require('../models/Budget');
const Expense = require('../models/Expense');

function getPeriodStart(period) {
    const now = new Date();
    if (period === 'monthly') {
        return new Date(now.getFullYear(), now.getMonth(), 1);
    }
    if (period === 'yearly') {
        return new Date(now.getFullYear(), 0, 1);
    }
    return null;
}

async function getBudgetAlerts(solutionCardId) {
    const budgets = await Budget.find({ solutionCardId });
    if (!budgets.length) return [];

    const alerts = [];

    for (const budget of budgets) {
        const filter = {
            solutionCard: solutionCardId,
            isDeleted: { $ne: true },
        };
        if (budget.category) filter.category = budget.category;

        const periodStart = getPeriodStart(budget.period);
        if (periodStart) filter.createdAt = { $gte: periodStart };

        const spentAgg = await Expense.aggregate([
            { $match: filter },
            { $group: { _id: null, total: { $sum: '$amount' } } },
        ]);
        const spent = spentAgg[0]?.total || 0;
        const limit = budget.limitAmount;
        const pct = limit > 0 ? (spent / limit) * 100 : 0;

        if (pct >= budget.alertThreshold) {
            alerts.push({
                budgetId: budget._id,
                category: budget.category || 'Overall',
                limitAmount: limit,
                spent,
                percentage: Math.round(pct),
                overspent: spent > limit,
                period: budget.period,
            });
        }
    }

    return alerts;
}

module.exports = { getBudgetAlerts };
