const mongoose = require('mongoose');

const CollectedCashSchema = new mongoose.Schema({
    solutionCardId: { type: mongoose.Schema.Types.ObjectId, ref: 'SolutionCard', required: true },
    name: { type: String, required: true },    // e.g., 'Nitin'
    amount: { type: Number, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // who added/updated
    collectedDate: { type: Date, default: Date.now },
}, {
    timestamps: { createdAt: 'collectedDate', updatedAt: 'updatedDate' }
});

CollectedCashSchema.index({ solutionCardId: 1, collectedDate: -1 });
CollectedCashSchema.index({ user: 1, collectedDate: -1 });

module.exports = mongoose.model('CollectedCash', CollectedCashSchema);
