const CollectedCash = require('../models/CollectedCash');
const { checkPermission } = require('../utils/checkPermission');
const { parsePagination, buildPaginatedResponse } = require('../utils/pagination');

exports.createCollectedCash = async (req, res, next) => {
    try {
        const { solutionCardId, name, amount, paymentMethod } = req.body;
        const userId = req.user.userId;

        if (!solutionCardId || !name || amount == null || amount === '') {
            return res.status(400).json({
                success: false,
                error: { code: 'BAD_REQUEST', message: 'solutionCardId, name, and amount are required.' },
            });
        }

        const numericAmount = Number(amount);
        if (!(numericAmount > 0)) {
            return res.status(400).json({
                success: false,
                error: { code: 'BAD_REQUEST', message: 'Amount must be greater than 0.' },
            });
        }

        const method = String(paymentMethod || 'cash').toLowerCase();
        if (!['cash', 'upi'].includes(method)) {
            return res.status(400).json({
                success: false,
                error: { code: 'BAD_REQUEST', message: 'paymentMethod must be cash or upi.' },
            });
        }

        const { role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const collectedCash = await CollectedCash.create({
            solutionCardId,
            name,
            amount: numericAmount,
            paymentMethod: method,
            user: userId,
        });

        res.status(201).json({ message: 'Collected cash added.', collectedCash, accessLevel });
    } catch (error) {
        next(error);
    }
};

exports.getCollectedCashBySolution = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;
        const { q, from, to } = req.query;
        const { page, limit, skip } = parsePagination(req.query);

        const { role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor', 'viewer'],
            allowOwner: true,
        });

        const filter = { solutionCardId };
        if (q) filter.name = { $regex: q, $options: 'i' };
        if (from || to) {
            filter.collectedDate = {};
            if (from) {
                if (/^\d{4}-\d{2}-\d{2}$/.test(from)) {
                    const [y, m, d] = from.split('-').map(Number);
                    filter.collectedDate.$gte = new Date(y, m - 1, d, 0, 0, 0, 0);
                } else {
                    filter.collectedDate.$gte = new Date(from);
                }
            }
            if (to) {
                if (/^\d{4}-\d{2}-\d{2}$/.test(to)) {
                    const [y, m, d] = to.split('-').map(Number);
                    filter.collectedDate.$lte = new Date(y, m - 1, d, 23, 59, 59, 999);
                } else {
                    filter.collectedDate.$lte = new Date(to);
                }
            }
        }

        const [total, collectedCash] = await Promise.all([
            CollectedCash.countDocuments(filter),
            CollectedCash.find(filter)
                .sort({ collectedDate: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
        ]);

        res.json(
            buildPaginatedResponse({
                data: collectedCash,
                page,
                limit,
                total,
                extra: { collectedCash, accessLevel },
            })
        );
    } catch (error) {
        next(error);
    }
};

exports.updateCollectedCash = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { name, amount, paymentMethod } = req.body;
        const userId = req.user.userId;

        const { role: accessLevel } = await checkPermission({
            resourceType: 'collectedCash',
            resourceId: id,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const update = { user: userId };
        if (name !== undefined) update.name = name;
        if (amount !== undefined) {
            const numericAmount = Number(amount);
            if (!(numericAmount > 0)) {
                return res.status(400).json({
                    success: false,
                    error: { code: 'BAD_REQUEST', message: 'Amount must be greater than 0.' },
                });
            }
            update.amount = numericAmount;
        }
        if (paymentMethod !== undefined) {
            const method = String(paymentMethod).toLowerCase();
            if (!['cash', 'upi'].includes(method)) {
                return res.status(400).json({
                    success: false,
                    error: { code: 'BAD_REQUEST', message: 'paymentMethod must be cash or upi.' },
                });
            }
            update.paymentMethod = method;
        }

        const updated = await CollectedCash.findByIdAndUpdate(id, update, { new: true });

        if (!updated) {
            return res.status(404).json({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Collected cash entry not found.' },
            });
        }

        res.json({ message: 'Collected cash updated.', collectedCash: updated, accessLevel });
    } catch (error) {
        next(error);
    }
};

exports.deleteCollectedCash = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;

        const { role: accessLevel } = await checkPermission({
            resourceType: 'collectedCash',
            resourceId: id,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        const deleted = await CollectedCash.findByIdAndDelete(id);
        if (!deleted) {
            return res.status(404).json({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Collected cash entry not found.' },
            });
        }

        res.json({ message: 'Collected cash entry deleted.', accessLevel });
    } catch (error) {
        next(error);
    }
};
