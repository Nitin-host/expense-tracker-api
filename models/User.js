const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true }
}, { _id: false });

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    role: {
        type: String,
        enum: ['super_admin', 'admin', 'user'],
        default: 'super_admin',
    },
    password: { type: String, required: true },
    tempPasswordExpiresAt: { type: Date, default: null },
    passwordChanged: { type: Boolean, default: false },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

    refreshTokens: [refreshTokenSchema]
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
