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

module.exports = mongoose.model('CollectedCash', CollectedCashSchema);
