const mongoose = require('mongoose');

const recurringExpenseSchema = new mongoose.Schema(
    {
        solutionCardId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'SolutionCard',
            required: true,
            index: true,
        },
        name: { type: String, required: true, trim: true },
        category: { type: String, required: true, trim: true },
        amount: { type: Number, required: true, min: 0 },
        paidAmount: { type: Number, required: true, min: 0 },
        paymentMethod: {
            type: String,
            enum: ['cash', 'upi'],
            default: 'cash',
        },
        frequency: {
            type: String,
            enum: ['weekly', 'monthly', 'yearly'],
            required: true,
        },
        nextRunAt: { type: Date, required: true },
        lastRunAt: { type: Date, default: null },
        isActive: { type: Boolean, default: true },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },
    },
    { timestamps: true }
);

module.exports = mongoose.model('RecurringExpense', recurringExpenseSchema);
