const mongoose = require('mongoose');

// Schema for shared users with roles
const sharedUserSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['editor', 'viewer'],
        required: true,
    },
}, { _id: false });


// Main SolutionCard schema
const solutionCardSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    year: {
        type: Number,
        required: true,
    },
    description: {
        type: String,
        default: '',
        trim: true,
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    sharedWith: [sharedUserSchema], // Array of shared users with roles

    // Soft delete support
    isDeleted: {
        type: Boolean,
        default: false,
    },
    deletedAt: {
        type: Date,
    },

    // Audit fields for last modification
    updatedAt: {
        type: Date,
        default: Date.now,
    },
    updatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    },

    createdAt: {
        type: Date,
        default: Date.now,
    },
});

// Middleware to update updatedAt on save/update
solutionCardSchema.pre('save', function (next) {
    this.updatedAt = new Date();
    next();
});

// Indexes for faster querying
solutionCardSchema.index({ owner: 1 });
solutionCardSchema.index({ 'sharedWith.user': 1 });

module.exports = mongoose.model('SolutionCard', solutionCardSchema);
