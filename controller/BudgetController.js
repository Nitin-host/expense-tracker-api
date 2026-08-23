const Budget = require('../models/Budget');
const { checkPermission } = require('../utils/checkPermission');
const { logAudit } = require('../utils/auditLog');
const { BadRequestError, NotFoundError } = require('../utils/Errors');

exports.listBudgets = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true,
        });

        const budgets = await Budget.find({ solutionCardId }).sort({ category: 1 });
        res.json({ budgets });
    } catch (error) {
        next(error);
    }
};

exports.createBudget = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;
        const { category, limitAmount, alertThreshold, period } = req.body;

        if (limitAmount == null || Number(limitAmount) < 0) {
            throw new BadRequestError('limitAmount is required and must be >= 0');
        }

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const budget = await Budget.create({
            solutionCardId,
            category: category?.trim() || '',
            limitAmount: Number(limitAmount),
            alertThreshold: alertThreshold ?? 80,
            period: period || 'all',
            createdBy: userId,
        });

        await logAudit({
            entityType: 'budget',
            entityId: budget._id,
            action: 'create',
            actorId: userId,
            solutionCardId,
            summary: `Budget set: ${budget.category || 'Overall'} ₹${budget.limitAmount}`,
        });

        res.status(201).json({ message: 'Budget created', budget });
    } catch (error) {
        next(error);
    }
};

exports.updateBudget = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;
        const budget = await Budget.findById(id);
        if (!budget) throw new NotFoundError('Budget not found');

        await checkPermission({
            resourceType: 'solution',
            resourceId: budget.solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const { category, limitAmount, alertThreshold, period } = req.body;
        if (category !== undefined) budget.category = category.trim();
        if (limitAmount != null) budget.limitAmount = Number(limitAmount);
        if (alertThreshold != null) budget.alertThreshold = alertThreshold;
        if (period) budget.period = period;
        await budget.save();

        await logAudit({
            entityType: 'budget',
            entityId: budget._id,
            action: 'update',
            actorId: userId,
            solutionCardId: budget.solutionCardId,
            summary: `Budget updated: ${budget.category || 'Overall'}`,
        });

        res.json({ message: 'Budget updated', budget });
    } catch (error) {
        next(error);
    }
};

exports.deleteBudget = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;
        const budget = await Budget.findById(id);
        if (!budget) throw new NotFoundError('Budget not found');

        await checkPermission({
            resourceType: 'solution',
            resourceId: budget.solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        await budget.deleteOne();
        await logAudit({
            entityType: 'budget',
            entityId: budget._id,
            action: 'delete',
            actorId: userId,
            solutionCardId: budget.solutionCardId,
            summary: `Budget deleted: ${budget.category || 'Overall'}`,
        });

        res.json({ message: 'Budget deleted' });
    } catch (error) {
        next(error);
    }
};
