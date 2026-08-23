const User = require('../models/User');
const SolutionCard = require('../models/SolutionCard')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendEmail } = require('../utils/Email');
const { buildUserWelcomeEmail, normalizeEmail } = require('../utils/userWelcomeEmail');
const { buildPasswordResetOtpEmail } = require('../utils/emailTemplate');
const { BadRequestError, UnauthorizedError, ForbiddenError, NotFoundError } = require('../utils/Errors');
require('dotenv').config();

// Token generation helpers
const generateAccessToken = (user) => {
    return jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
};

const generateRefreshToken = () => {
    return crypto.randomBytes(64).toString('hex');
};

const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const createUser = async (req, res, next) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) throw new BadRequestError('All fields are required.');

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) throw new BadRequestError('User with this email already exists.');

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            passwordChanged: true,
            refreshTokens: [],
        });

        await user.save();
        res.status(201).json({ message: 'User successfully created', userId: user._id });
    } catch (error) {
        next(error);
    }
};

// const login = async (req, res, next) => {
//     try {
//         const { email, password } = req.body;

//         if (!email || !password) {
//             return res.status(400).json({ message: 'Email and password are required' });
//         }

//         const user = await User.findOne({ email: email.toLowerCase() });
//         if (!user) return res.status(400).json({ message: 'Invalid credentials' });

//         const isMatch = await bcrypt.compare(password, user.password);
//         if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

//         const accessToken = generateAccessToken(user);

//         // Check for existing unexpired refresh token
//         const existingToken = user.refreshTokens.find(rt => rt.expiresAt > new Date());

//         let refreshToken;
//         if (existingToken) {
//             refreshToken = existingToken.token;
//         } else {
//             refreshToken = generateRefreshToken();
//             user.refreshTokens.push({
//                 token: refreshToken,
//                 expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
//             });
//             await user.save();
//         }

//         res.cookie('refreshToken', refreshToken, {
//             httpOnly: true,
//             secure: true,
//             sameSite: 'Strict',
//             maxAge: 7 * 24 * 60 * 60 * 1000,
//         });

//         res.json({
//             message: 'Login successful',
//             token: accessToken,
//             user: {
//                 id: user._id,
//                 name: user.name,
//                 email: user.email,
//                 role: user.role
//             }
//         });
//     } catch (err) {
//         next(err);
//     }
// };

const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: { code: 'BAD_REQUEST', message: 'Email and password are required' },
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(400).json({
                success: false,
                error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials' },
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({
                success: false,
                error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials' },
            });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken();

        user.refreshTokens = (user.refreshTokens || []).filter((rt) => rt.expiresAt > new Date());
        user.refreshTokens.push({
            token: refreshToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });
        await user.save();

        const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        };
        res.cookie('refreshToken', refreshToken, cookieOptions);

        res.json({
            message: 'Login successful',
            token: accessToken,
            refreshToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        next(err);
    }
};

const refreshAccessToken = async (req, res, next) => {
    const token = req.body?.refreshToken || req.cookies?.refreshToken;
    if (!token) {
        return res.status(401).json({
            success: false,
            error: { code: 'NO_REFRESH_TOKEN', message: 'No refresh token provided' },
        });
    }

    try {
        const user = await User.findOne({ 'refreshTokens.token': token });
        if (!user) {
            return res.status(403).json({
                success: false,
                error: { code: 'INVALID_REFRESH', message: 'Invalid refresh token' },
            });
        }

        const oldToken = user.refreshTokens.find(rt => rt.token === token);
        if (!oldToken || oldToken.expiresAt < new Date()) {
            return res.status(403).json({
                success: false,
                error: { code: 'REFRESH_EXPIRED', message: 'Refresh token expired' },
            });
        }

        user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== token);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken();

        user.refreshTokens.push({
            token: newRefreshToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        await user.save();

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({ token: newAccessToken, refreshToken: newRefreshToken });
    } catch (err) {
        console.error('Refresh error:', err);
        next(err);
    }
};

const logout = async (req, res, next) => {
    try {
        const token = req.body?.refreshToken || req.cookies?.refreshToken;
        if (!token) return res.status(204).send();

        const user = await User.findOne({ 'refreshTokens.token': token });
        if (user) {
            user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== token);
            await user.save();
        }

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
        });
        res.status(204).send();
    } catch (err) {
        next(err);
    }
};

const changePassword = async (req, res, next) => {
    try {
        const { email, oldPassword, newPassword } = req.body;

        if (!email || !oldPassword || !newPassword) {
            throw new BadRequestError('Email, old password, and new password are required');
        }

        const user = await User.findOne({ email: email.toLowerCase() }).select('+password +tempPasswordExpiresAt');
        if (!user) {
            throw new BadRequestError('User not found');
        }

        // Check temp password expiry
        if (user.tempPasswordExpiresAt) {
            if (new Date() > user.tempPasswordExpiresAt) {
                throw new ForbiddenError('Temporary password expired. Please request a new password reset.');
            }
        } else {
            throw new ForbiddenError('Temporary password not set.');
        }

        // Check if old password matches temp password
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            throw new ForbiddenError('Temporary password is incorrect');
        }

        // Update password
        user.password = await bcrypt.hash(newPassword, 10);
        user.passwordChanged = true;
        user.tempPasswordExpiresAt = null;
        await user.save();

        res.json({ message: 'Password updated successfully' });

    } catch (error) {
        next(error);
    }
};

const createUserBySuperAdmin = async (req, res, next) => {
    try {
        const { name, email, role } = req.body;
        if (!name || !email || !role) throw new BadRequestError('Name, email, and role are required.');

        const normalizedEmail = normalizeEmail(email);
        if (!normalizedEmail) throw new BadRequestError('Valid email is required.');

        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            throw new BadRequestError(
                'A user with this email already exists. Check the users list — they may have registered directly or were created earlier.'
            );
        }

        const tempPassword = crypto.randomBytes(6).toString('hex');
        const hashedTempPassword = await bcrypt.hash(tempPassword, 10);
        const tempPasswordExpiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);

        const { html, text } = await buildUserWelcomeEmail({
            name,
            tempPassword,
            email: normalizedEmail,
        });

        const messageId = await sendEmail(
            normalizedEmail,
            'Your Account Created - Expense Tracker',
            html,
            text
        );

        const newUser = new User({
            name,
            email: normalizedEmail,
            role,
            password: hashedTempPassword,
            tempPasswordExpiresAt,
            passwordChanged: false,
            createdBy: req.user?.userId || null,
            refreshTokens: [],
        });

        await newUser.save();

        res.status(201).json({
            message: `User created. Welcome email sent to ${normalizedEmail}.`,
            emailSent: true,
            messageId,
            userId: newUser._id,
        });
    } catch (error) {
        next(error);
    }
};

const getCreatedUsers = async (req, res, next) => {
    try {
        const creatorId = req.user.userId;
        const role = req.user.role;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
        const skip = (page - 1) * limit;

        const filter =
            role === 'super_admin'
                ? { _id: { $ne: creatorId } }
                : { createdBy: creatorId };

        const [users, total] = await Promise.all([
            User.find(filter)
                .select('-password -refreshTokens')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            User.countDocuments(filter),
        ]);

        res.json({
            data: users,
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit) || 1,
        });
    } catch (error) {
        next(error);
    }
};

const requestTempPassword = async (req, res, next) => {
    try {
        const { email } = req.body;
        if (!email) throw new BadRequestError('Email is required.');

        const normalizedEmail = normalizeEmail(email);
        const genericSuccess = { message: "If your email is registered, you'll receive instructions shortly." };

        const user = await User.findOne({ email: normalizedEmail });
        if (!user) return res.json(genericSuccess);

        const tempPassword = crypto.randomBytes(6).toString('hex');
        const hashedTempPassword = await bcrypt.hash(tempPassword, 10);
        const tempPasswordExpiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);

        const { html, text } = await buildUserWelcomeEmail({
            name: user.name,
            tempPassword,
            email: normalizedEmail,
        });

        await sendEmail(normalizedEmail, 'Reset your Password - Expense Tracker', html, text);

        user.password = hashedTempPassword;
        user.tempPasswordExpiresAt = tempPasswordExpiresAt;
        user.passwordChanged = false;
        await user.save();

        res.json(genericSuccess);
    } catch (error) {
        next(error);
    }
};

const changeUserRole = async (req, res, next) => {
    try {
        // Super admin only, enforce in route middleware too
        const { userId, newRole } = req.body;

        if (!userId || !newRole) {
            throw new BadRequestError('User ID and new role are required.');
        }

        if (!['user', 'admin', 'super_admin'].includes(newRole)) {
            throw new BadRequestError('Invalid role specified.');
        }

        const user = await User.findById(userId);
        if (!user) throw new NotFoundError('User not found.');

        // Optional: prevent super_admin demoting themselves or other critical logic

        user.role = newRole;
        await user.save();

        res.json({ message: 'User role updated successfully.', user });
    } catch (err) {
        next(err);
    }
};

const getAllUsers = async (req, res, next) => {
    try {
        const currentUserId = req.user.userId;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));
        const skip = (page - 1) * limit;
        const filter = { _id: { $ne: currentUserId } };

        const [users, total] = await Promise.all([
            User.find(filter, 'name email role').sort({ name: 1 }).skip(skip).limit(limit).lean(),
            User.countDocuments(filter),
        ]);

        res.json({
            data: users,
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit) || 1,
        });
    } catch (error) {
        next(error);
    }
};

const getUsersForSharing = async (req, res, next) => {
    try {
        const { solutionCardId } = req.query;
        const q = String(req.query.q || '').trim();
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));

        if (!solutionCardId) {
            return res.status(400).json({ message: 'SolutionCard ID required' });
        }

        const solutionCard = await SolutionCard.findById(solutionCardId).select('owner sharedWith').lean();
        if (!solutionCard) return res.status(404).json({ message: 'Solution card not found' });

        const excludedUserIds = [
            solutionCard.owner.toString(),
            ...(solutionCard.sharedWith || []).map((su) => su.user.toString()),
        ];

        const filter = {
            _id: { $nin: excludedUserIds },
        };
        if (q) {
            filter.$or = [
                { name: { $regex: q, $options: 'i' } },
                { email: { $regex: q, $options: 'i' } },
            ];
        }

        const users = await User.find(filter, 'name email role')
            .sort({ name: 1 })
            .limit(limit)
            .lean();

        res.json(users);
    } catch (error) {
        next(error);
    }
};

// Controller for super admin to delete users
const deleteUserBySuperAdmin = async (req, res, next) => {
    try {
        // Ensure requester is super_admin
        if (req.user.role !== 'super_admin') {
            throw new ForbiddenError('Only super admins can delete users.');
        }

        const { userId } = req.params;
        if (!userId) {
            throw new BadRequestError('User ID is required.');
        }

        if (req.user.userId === userId) {
            throw new ForbiddenError('Super admins cannot delete themselves.');
        }

        const user = await User.findById(userId);
        if (!user) throw new NotFoundError('User not found.');

        // Delete the user
        await User.findByIdAndDelete(userId);

        // Remove this user from all solution cards sharedWith arrays
        await SolutionCard.updateMany(
            { 'sharedWith.user': userId },
            { $pull: { sharedWith: { user: userId } } }
        );

        // Optional: Also clean other related data here if needed

        res.json({ message: 'User deleted successfully and removed from shared solution cards.' });
    } catch (error) {
        next(error);
    }
};

const sendPasswordResetOTP = async (req, res, next) => {
    try {
        const { email } = req.body;
        if (!email) throw new BadRequestError('Email is required');

        const normalizedEmail = normalizeEmail(email);
        const genericSuccess = { message: "If your email is registered, you'll receive an OTP." };

        const user = await User.findOne({ email: normalizedEmail });
        if (!user) return res.json(genericSuccess);

        const otp = generateOTP();
        const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
        const hashedOTP = await bcrypt.hash(otp, 10);

        const { html, text } = await buildPasswordResetOtpEmail({
            name: user.name,
            otp,
            expiryMinutes: 10,
        });

        await sendEmail(normalizedEmail, 'Password Reset OTP - Expense Tracker', html, text);

        user.passwordResetOTP = hashedOTP;
        user.passwordResetOTPExpiresAt = otpExpiresAt;
        await user.save();

        res.json(genericSuccess);
    } catch (error) {
        next(error);
    }
};

const verifyPasswordResetOTP = async (req, res, next) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) throw new BadRequestError('Email and OTP are required');

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) throw new UnauthorizedError('Invalid email or OTP');

        if (!user.passwordResetOTP || !user.passwordResetOTPExpiresAt) {
            throw new UnauthorizedError('No OTP requested for this user');
        }

        if (user.passwordResetOTPExpiresAt < new Date()) {
            throw new UnauthorizedError('OTP has expired');
        }

        const validOTP = await bcrypt.compare(otp, user.passwordResetOTP);
        if (!validOTP) throw new UnauthorizedError('Invalid OTP');

        // OTP is valid, clear it to prevent reuse
        user.passwordResetOTP = null;
        user.passwordResetOTPExpiresAt = null;
        await user.save();

        res.json({ message: 'OTP verified successfully. You may now reset your password.' });
    } catch (error) {
        next(error);
    }
};

const resetPassword = async (req, res, next) => {
    try {
        const { email, newPassword } = req.body;
        if (!email || !newPassword) throw new BadRequestError('Email and new password are required');

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) throw new NotFoundError('User not found');

        // Optionally you can enforce that OTP verification is done by checking a flag or trust that frontend called verify OTP first.

        user.password = await bcrypt.hash(newPassword, 10);
        user.passwordChanged = true;  // mark password as changed
        await user.save();

        res.json({ message: 'Password has been reset successfully.' });
    } catch (error) {
        next(error);
    }
};

module.exports = {
    createUser,
    login,
    refreshAccessToken,
    logout,
    changePassword,
    createUserBySuperAdmin,
    requestTempPassword,
    getCreatedUsers,
    changeUserRole,
    getAllUsers,
    getUsersForSharing,
    deleteUserBySuperAdmin,
    sendPasswordResetOTP,
    verifyPasswordResetOTP,
    resetPassword
};
