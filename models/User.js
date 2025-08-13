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
        default: 'user',
    },
    password: { type: String, required: true },
    passwordChanged: { type: Boolean, default: false },
    tempPasswordExpiresAt: { type: Date, default: null },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

    refreshTokens: [refreshTokenSchema],

    // For forgot password OTP flow:
    passwordResetOTP: { type: String, default: null },           // Store OTP code (hashed or plain text)
    passwordResetOTPExpiresAt: { type: Date, default: null }     // Expiry of OTP
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
