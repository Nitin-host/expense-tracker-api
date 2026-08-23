const RecurringExpense = require('../models/RecurringExpense');
const Expense = require('../models/Expense');
const { checkPermission } = require('../utils/checkPermission');
const { logAudit } = require('../utils/auditLog');
const { BadRequestError, NotFoundError } = require('../utils/Errors');

function addInterval(date, frequency) {
    const d = new Date(date);
    if (frequency === 'weekly') d.setDate(d.getDate() + 7);
    else if (frequency === 'monthly') d.setMonth(d.getMonth() + 1);
    else if (frequency === 'yearly') d.setFullYear(d.getFullYear() + 1);
    return d;
}

exports.listRecurring = async (req, res, next) => {
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

        const items = await RecurringExpense.find({ solutionCardId }).sort({ nextRunAt: 1 });
        res.json({ recurringExpenses: items });
    } catch (error) {
        next(error);
    }
};

exports.createRecurring = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;
        const { name, category, amount, paidAmount, paymentMethod, frequency, nextRunAt } = req.body;

        if (!name || !category || amount == null || paidAmount == null || !frequency) {
            throw new BadRequestError('name, category, amount, paidAmount, and frequency are required');
        }

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const item = await RecurringExpense.create({
            solutionCardId,
            name,
            category,
            amount: Number(amount),
            paidAmount: Number(paidAmount),
            paymentMethod: paymentMethod || 'cash',
            frequency,
            nextRunAt: nextRunAt ? new Date(nextRunAt) : new Date(),
            createdBy: userId,
        });

        await logAudit({
            entityType: 'recurringExpense',
            entityId: item._id,
            action: 'create',
            actorId: userId,
            solutionCardId,
            summary: `Recurring expense: ${name}`,
        });

        res.status(201).json({ message: 'Recurring expense created', recurringExpense: item });
    } catch (error) {
        next(error);
    }
};

exports.updateRecurring = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;
        const item = await RecurringExpense.findById(id);
        if (!item) throw new NotFoundError('Recurring expense not found');

        await checkPermission({
            resourceType: 'solution',
            resourceId: item.solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const fields = ['name', 'category', 'amount', 'paidAmount', 'paymentMethod', 'frequency', 'nextRunAt', 'isActive'];
        fields.forEach((f) => {
            if (req.body[f] !== undefined) item[f] = req.body[f];
        });
        if (req.body.nextRunAt) item.nextRunAt = new Date(req.body.nextRunAt);
        await item.save();

        res.json({ message: 'Recurring expense updated', recurringExpense: item });
    } catch (error) {
        next(error);
    }
};

exports.deleteRecurring = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;
        const item = await RecurringExpense.findById(id);
        if (!item) throw new NotFoundError('Recurring expense not found');

        await checkPermission({
            resourceType: 'solution',
            resourceId: item.solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        await item.deleteOne();
        res.json({ message: 'Recurring expense deleted' });
    } catch (error) {
        next(error);
    }
};

exports.processDueRecurring = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const now = new Date();
        const due = await RecurringExpense.find({
            solutionCardId,
            isActive: true,
            nextRunAt: { $lte: now },
        });

        const created = [];
        for (const item of due) {
            const expense = await Expense.create({
                name: item.name,
                category: item.category,
                amount: item.amount,
                payments: [{
                    paidAmount: item.paidAmount,
                    paymentMethod: item.paymentMethod,
                    paidAt: now,
                }],
                paidBy: userId,
                solutionCard: solutionCardId,
            });
            item.lastRunAt = now;
            item.nextRunAt = addInterval(now, item.frequency);
            await item.save();
            created.push(expense);
        }

        res.json({ message: `${created.length} recurring expense(s) processed`, created: created.length });
    } catch (error) {
        next(error);
    }
};
