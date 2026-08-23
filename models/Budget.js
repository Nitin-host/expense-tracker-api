const mongoose = require('mongoose');

const budgetSchema = new mongoose.Schema(
    {
        solutionCardId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'SolutionCard',
            required: true,
            index: true,
        },
        category: {
            type: String,
            trim: true,
            default: '',
        },
        limitAmount: {
            type: Number,
            required: true,
            min: 0,
        },
        alertThreshold: {
            type: Number,
            default: 80,
            min: 1,
            max: 100,
        },
        period: {
            type: String,
            enum: ['all', 'monthly', 'yearly'],
            default: 'all',
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
        },
    },
    { timestamps: true }
);

budgetSchema.index({ solutionCardId: 1, category: 1 });

module.exports = mongoose.model('Budget', budgetSchema);
