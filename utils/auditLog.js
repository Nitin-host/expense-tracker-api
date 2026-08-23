const AuditLog = require('../models/AuditLog');

async function logAudit({
    entityType,
    entityId,
    action,
    actorId,
    actorName = '',
    solutionCardId = null,
    summary = '',
    metadata = {},
}) {
    try {
        await AuditLog.create({
            entityType,
            entityId,
            action,
            actorId,
            actorName,
            solutionCardId,
            summary,
            metadata,
        });
    } catch (err) {
        console.error('Audit log failed:', err.message);
    }
}

module.exports = { logAudit };
