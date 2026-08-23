const CollectedCash = require('../models/CollectedCash');
const { checkPermission } = require('../utils/checkPermission');
const { parsePagination, buildPaginatedResponse } = require('../utils/pagination');

exports.createCollectedCash = async (req, res, next) => {
    try {
        const { solutionCardId, name, amount, paymentMethod } = req.body;
        const userId = req.user.userId;

        if (!solutionCardId || !name || !amount) {
            return res.status(400).json({
                success: false,
                error: { code: 'BAD_REQUEST', message: 'solutionCardId, name, and amount are required.' },
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
            amount,
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
            if (from) filter.collectedDate.$gte = new Date(from);
            if (to) filter.collectedDate.$lte = new Date(to);
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

        const update = { name, amount, user: userId };
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
