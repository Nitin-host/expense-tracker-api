const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
    {
        entityType: {
            type: String,
            required: true,
            enum: ['expense', 'collectedCash', 'solution', 'budget', 'recurringExpense', 'user'],
        },
        entityId: { type: mongoose.Schema.Types.ObjectId },
        action: {
            type: String,
            required: true,
            enum: ['create', 'update', 'delete', 'restore', 'share', 'login'],
        },
        actorId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },
        actorName: { type: String, default: '' },
        solutionCardId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'SolutionCard',
            index: true,
        },
        summary: { type: String, default: '' },
        metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    },
    { timestamps: { createdAt: true, updatedAt: false } }
);

auditLogSchema.index({ createdAt: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
