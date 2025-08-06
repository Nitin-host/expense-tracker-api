const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
    paidAmount: { type: Number, required: true, min: 0 },
    paidAt: { type: Date, default: Date.now },
    paymentMethod: { type: String, enum: ['cash', 'upi'], required: true },
    upiScreenshotUrls: [{ type: String }],         // Array of Cloudinary URLs
    upiScreenshotPublicIds: [{ type: String }],    // Array of Cloudinary public IDs
}, { _id: false });

const expenseSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },      // Who is adding
    category: { type: String, required: true, trim: true },  // e.g., DJ, Pooja Samanulu
    amount: { type: Number, required: true, min: 0 },        // Total bill amount
    payments: [paymentSchema],                               // Payment records (advance, balance, etc.)
    advancePaid: { type: Number, default: 0, min: 0 },       // Aggregated (update on payments)
    pendingAmount: { type: Number, min: 0 },                 // Calculated: amount - advancePaid
    paymentStatus: {
        type: String,
        enum: ['pending', 'partially_paid', 'fully_paid'],
        default: 'pending'
    },                                                       // Status string
    solutionCard: { type: mongoose.Schema.Types.ObjectId, ref: 'SolutionCard', required: true },
    isDeleted: {
        type: Boolean,
        default: false,
    },
    paidBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // User adding the expense
    // createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Auto-update advancePaid, pendingAmount, paymentStatus before saving
expenseSchema.pre('save', function (next) {
    this.advancePaid = this.payments.reduce((sum, p) => sum + p.paidAmount, 0);
    this.pendingAmount = Math.max(this.amount - this.advancePaid, 0);
    if (this.pendingAmount === 0) this.paymentStatus = 'fully_paid';
    else if (this.advancePaid > 0) this.paymentStatus = 'partially_paid';
    else this.paymentStatus = 'pending';
    next();
});

module.exports = mongoose.model('Expense', expenseSchema);
