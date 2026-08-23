const AuditLog = require('../models/AuditLog');

exports.listAuditLogs = async (req, res, next) => {
    try {
        const { solutionCardId } = req.query;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, parseInt(req.query.limit, 10) || 50);
        const skip = (page - 1) * limit;

        const filter = {};
        if (solutionCardId) filter.solutionCardId = solutionCardId;

        const [total, logs] = await Promise.all([
            AuditLog.countDocuments(filter),
            AuditLog.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .populate('actorId', 'name email')
                .lean(),
        ]);

        res.json({
            data: logs,
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit) || 1,
        });
    } catch (error) {
        next(error);
    }
};

exports.listAuditLogsForSolution = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, parseInt(req.query.limit, 10) || 50);
        const skip = (page - 1) * limit;

        const filter = { solutionCardId };

        const [total, logs] = await Promise.all([
            AuditLog.countDocuments(filter),
            AuditLog.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .populate('actorId', 'name email')
                .lean(),
        ]);

        res.json({
            data: logs,
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit) || 1,
        });
    } catch (error) {
        next(error);
    }
};
