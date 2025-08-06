const User = require('../models/User');
const SolutionCard = require('../models/SolutionCard')
const bcrypt = require('bcrypt');
const fs = require('fs/promises');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendEmail } = require('../utils/Email');
const { BadRequestError, UnauthorizedError, ForbiddenError, NotFoundError } = require('../utils/Errors');
require('dotenv').config();

// Token generation helpers
const generateAccessToken = (user) => {
    return jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
    );
};

const generateRefreshToken = () => {
    return crypto.randomBytes(64).toString('hex');
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

const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const accessToken = generateAccessToken(user);

        // Check for existing unexpired refresh token
        const existingToken = user.refreshTokens.find(rt => rt.expiresAt > new Date());

        let refreshToken;
        if (existingToken) {
            refreshToken = existingToken.token;
        } else {
            refreshToken = generateRefreshToken();
            user.refreshTokens.push({
                token: refreshToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
            });
            await user.save();
        }

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({
            message: 'Login successful',
            token: accessToken,
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
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ message: 'No refresh token provided' });

    try {
        // Find the user who has this refresh token
        const user = await User.findOne({ 'refreshTokens.token': token });
        if (!user) return res.status(403).json({ message: 'Invalid refresh token' });

        // Get token object
        const oldToken = user.refreshTokens.find(rt => rt.token === token);
        if (!oldToken || oldToken.expiresAt < new Date()) {
            return res.status(403).json({ message: 'Refresh token expired' });
        }

        // Remove old token
        user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== token);

        // Generate new tokens
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken();

        // Save new refresh token
        user.refreshTokens.push({
            token: newRefreshToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });

        await user.save();

        // Set new refresh token in cookie
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ token: newAccessToken });
    } catch (err) {
        console.error('Refresh error:', err);
        next(err);
    }
};

const logout = async (req, res, next) => {
    try {
        const token = req.cookies.refreshToken;
        if (!token) return res.status(204).send();

        const user = await User.findOne({ 'refreshTokens.token': token });
        if (user) {
            user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== token);
            await user.save();
        }

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: true,
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
            throw new BadRequestError('Email, old password and new password are required.');
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) throw new NotFoundError('User not found.');

        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) throw new UnauthorizedError('Old password is incorrect.');

        if (!user.passwordChanged) {
            const now = new Date();
            if (!user.tempPasswordExpiresAt || user.tempPasswordExpiresAt < now) {
                throw new ForbiddenError('Temporary password expired. Please request a new password reset.');
            }
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.passwordChanged = true;
        user.tempPasswordExpiresAt = null;
        await user.save();

        res.json({ message: 'Password changed successfully.' });
    } catch (error) {
        next(error);
    }
};

const createUserBySuperAdmin = async (req, res, next) => {
    try {
        const { name, email, role } = req.body;
        if (!name || !email || !role) throw new BadRequestError('Name, email, and role are required.');

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) throw new BadRequestError('User with this email already exists.');

        const tempPassword = crypto.randomBytes(6).toString('hex');
        const hashedTempPassword = await bcrypt.hash(tempPassword, 10);
        const tempPasswordExpiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);

        const newUser = new User({
            name,
            email: email.toLowerCase(),
            role,
            password: hashedTempPassword,
            tempPasswordExpiresAt,
            passwordChanged: false,
            createdBy: req.user && req.user._id,
            refreshTokens: [],
        });

        await newUser.save();

        const resetLink = `https://expense-tracker-nitins.vercel.app/change-password?email=${encodeURIComponent(email)}&temp=true`;
        const templatePath = path.join(__dirname, '..', 'templates', 'userCreationEmail.html');
        let htmlTemplate = await fs.readFile(templatePath, 'utf-8');

        htmlTemplate = htmlTemplate.replace(/{{name}}/g, name)
            .replace(/{{tempPassword}}/g, tempPassword)
            .replace(/{{resetLink}}/g, resetLink);

        await sendEmail(email, 'Your Account Created - Vinayaka Chavithi Expense Tracker', htmlTemplate);
        res.status(201).json({ message: 'User created and email sent.' });
    } catch (error) {
        next(error);
    }
};

const getCreatedUsers = async (req, res, next) => {
    try {
        // req.user is populated by authenticateToken middleware (should contain _id and role)
        const creatorId = req.user._id;
        const users = await User.find({ createdBy: creatorId })
            .select('-password -refreshTokens') // exclude sensitive fields
            .sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        next(error);
    }
};

const requestTempPassword = async (req, res, next) => {
    try {
        const { email } = req.body;
        if (!email) throw new BadRequestError('Email is required.');

        const user = await User.findOne({ email: email.toLowerCase() });
        const genericSuccess = { message: "If your email is registered, you'll receive instructions shortly." };
        if (!user) return res.json(genericSuccess);

        const tempPassword = crypto.randomBytes(6).toString('hex');
        const hashedTempPassword = await bcrypt.hash(tempPassword, 10);
        const tempPasswordExpiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);

        user.password = hashedTempPassword;
        user.tempPasswordExpiresAt = tempPasswordExpiresAt;
        user.passwordChanged = false;
        await user.save();

        const resetLink = `https://your-frontend-url.com/change-password?email=${encodeURIComponent(email)}&temp=true`;
        const templatePath = path.join(__dirname, '..', 'templates', 'userCreationEmail.html');
        let htmlTemplate = await fs.readFile(templatePath, 'utf-8');

        htmlTemplate = htmlTemplate.replace(/{{name}}/g, user.name)
            .replace(/{{tempPassword}}/g, tempPassword)
            .replace(/{{resetLink}}/g, resetLink);

        await sendEmail(email, 'Reset your Password - Vinayaka Chavithi Tracker', htmlTemplate);
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

        // Find all users except the currently logged-in user
        const users = await User.find({ _id: { $ne: currentUserId } }, 'name email role')
            .sort({ name: 1 });

        res.json(users);
    } catch (error) {
        next(error);
    }
};

const getUsersForSharing = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { solutionCardId } = req.query;

        if (!solutionCardId) {
            return res.status(400).json({ message: 'SolutionCard ID required' });
        }

        const solutionCard = await SolutionCard.findById(solutionCardId);
        if (!solutionCard) return res.status(404).json({ message: 'Solution card not found' });

        const excludedUserIds = [
            solutionCard.owner.toString(),
            ...solutionCard.sharedWith.map(su => su.user.toString()),
        ];

        const users = await User.find({
            _id: { $nin: excludedUserIds },
        }, 'name email role').sort({ name: 1 });

        res.json(users);
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
    getUsersForSharing
};
