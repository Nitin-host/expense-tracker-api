const SolutionCard = require('../models/SolutionCard');
const User = require('../models/User');
const { BadRequestError, NotFoundError, ForbiddenError } = require('../utils/Errors');
const { checkPermission } = require('../utils/checkPermission');
const { sendEmail } = require('../utils/Email');
const { buildSolutionSharedEmail } = require('../utils/emailTemplate');
const { parsePagination, buildPaginatedResponse } = require('../utils/pagination');
require('dotenv').config();

function normalizeUserId(value) {
    if (value == null) return null;
    if (typeof value === 'object' && value._id != null) return String(value._id);
    return String(value);
}

// Helper: check if user has access, returns role or null
const getUserRoleOnCard = (solutionCard, userId) => {
    if (solutionCard.owner.equals(userId)) return 'owner';

    const sharedUser = solutionCard.sharedWith.find(s => s.user.equals(userId));
    if (!sharedUser) return null;

    return sharedUser.role; // editor or viewer
};

// Create a Solution Card
const createSolutionCard = async (req, res, next) => {
    try {
        const { name, year, sharedWith, description } = req.body;

        if (!name || !year) {
            throw new BadRequestError('Name and year are required');
        }

        const solutionCard = new SolutionCard({
            name: name.trim(),
            year,
            description: description ? description.trim() : '', // Add description here
            owner: req.user.userId,
            sharedWith: sharedWith || [],
            isDeleted: false,
            deletedAt: null,
        });

        await solutionCard.save();

        res.status(201).json({ message: 'Solution card created successfully', solutionCard });
    } catch (error) {
        next(error);
    }
};

// Get all Solution Cards accessible by user (owner or shared), excluding soft deleted
const getSolutionCards = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { page, limit, skip } = parsePagination(req.query, { defaultLimit: 24, maxLimit: 50 });

        const filter = {
            isDeleted: false,
            $or: [
                { owner: userId },
                { 'sharedWith.user': userId },
            ],
        };

        const [total, cards] = await Promise.all([
            SolutionCard.countDocuments(filter),
            SolutionCard.find(filter)
                .sort({ year: -1 })
                .skip(skip)
                .limit(limit)
                .populate({ path: 'sharedWith.user', select: 'name email' })
                .populate({ path: 'owner', select: 'name email' }),
        ]);

        const transformed = cards.map(card => {
            const sharedWith = card.sharedWith.map(su => ({
                user: su.user._id,
                name: su.user.name,
                email: su.user.email,
                role: su.role,
            }));

            return {
                ...card.toObject(),
                owner: { _id: card.owner._id, name: card.owner.name, email: card.owner.email },
                sharedWith,
            };
        });

        res.json(
            buildPaginatedResponse({
                data: transformed,
                page,
                limit,
                total,
                // Backward-compatible: clients that expect a bare array still get data via .data
                // Also spread array-like for older clients that check Array.isArray — keep `data` primary
            })
        );
    } catch (error) {
        next(error);
    }
};

// Get all soft-deleted Solution Cards owned by the user
const getDeletedSolutionCards = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const userRole = req.user.role;  // Assuming your auth middleware sets req.user.role

        // Allow only super_admin to access deleted solution cards
        if (userRole !== 'super_admin') {
            return res.status(403).json({ message: 'Access denied: super_admins only.' });
        }

        const cards = await SolutionCard.find({
            isDeleted: true,
        }).sort({ deletedAt: -1 });

        res.json(cards);
    } catch (error) {
        next(error);
    }
};

// Get a single Solution Card by ID with access check, exclude if deleted
const getSolutionCardById = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;

        const card = await SolutionCard.findById(id);
        if (!card || card.isDeleted) {
            throw new NotFoundError('Solution card not found');
        }

        const role = getUserRoleOnCard(card, userId);

        if (!role) {
            throw new ForbiddenError('Access denied');
        }

        res.json({ solutionCard: card, role });
    } catch (error) {
        next(error);
    }
};

// Update solution card (only owner can update, including sharedWith list)
const updateSolutionCard = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { name, year, sharedWith, description } = req.body;
        const userId = req.user.userId;

        const card = await SolutionCard.findById(id);
        if (!card || card.isDeleted) {
            throw new NotFoundError('Solution card not found');
        }

        if (!card.owner.equals(userId)) {
            throw new ForbiddenError('Only owner can update this solution card');
        }

        if (name) card.name = name.trim();
        if (year) card.year = year;
        if (description !== undefined) card.description = description.trim();

        if (sharedWith) {
            if (!Array.isArray(sharedWith)) throw new BadRequestError('sharedWith must be an array');

            for (const item of sharedWith) {
                if (!item.user || !item.role) {
                    throw new BadRequestError('Each sharedWith item must have user and role');
                }
                if (!['editor', 'viewer'].includes(item.role)) {
                    throw new BadRequestError('Role must be either editor or viewer');
                }
            }

            card.sharedWith = sharedWith;
        }

        await card.save();

        res.json({ message: 'Solution card updated successfully', solutionCard: card });
    } catch (error) {
        next(error);
    }
};

// POST /api/solution/:id/share
const shareSolutionCard = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { sharedWith, notifyUsers, notifyUserIds } = req.body;
        const userId = req.user.userId;

        const card = await SolutionCard.findById(id);
        if (!card || card.isDeleted)
            throw new NotFoundError('Solution card not found');

        if (!card.owner.equals(userId)) {
            throw new ForbiddenError('Only owner can update this solution card sharing');
        }

        if (!Array.isArray(sharedWith)) {
            throw new BadRequestError('sharedWith must be an array');
        }

        const oldSharedUserIds = new Set(
            (card.sharedWith || []).map((u) => normalizeUserId(u.user)).filter(Boolean)
        );

        for (const item of sharedWith) {
            if (!item.user || !item.role) {
                throw new BadRequestError('Each sharedWith item must have user and role');
            }
            if (!['editor', 'viewer'].includes(item.role)) {
                throw new BadRequestError('Role must be either editor or viewer');
            }
        }

        const userIds = [
            ...new Set(sharedWith.map((item) => normalizeUserId(item.user)).filter(Boolean)),
        ];
        const users = await User.find({ _id: { $in: userIds } }).select('name email').lean();
        const userMap = Object.fromEntries(users.map((u) => [u._id.toString(), u]));

        const enriched = sharedWith.map((item) => {
            const userIdKey = normalizeUserId(item.user);
            const user = userMap[userIdKey];
            if (!user) throw new NotFoundError(`User ${item.user} not found`);
            return {
                user: user._id,
                name: user.name,
                email: user.email,
                role: item.role,
            };
        });

        card.sharedWith = enriched;
        await card.save();

        let emailsSent = 0;
        const emailErrors = [];

        if (notifyUsers) {
            const owner = await User.findById(userId).select('name').lean();
            const explicitNotifyIds = new Set(
                (Array.isArray(notifyUserIds) ? notifyUserIds : [])
                    .map(normalizeUserId)
                    .filter(Boolean)
            );

            const toNotify = enriched.filter((u) => {
                const id = normalizeUserId(u.user);
                return !oldSharedUserIds.has(id) || explicitNotifyIds.has(id);
            });

            const results = await Promise.allSettled(
                toNotify.map(async (user) => {
                    const { html, text } = await buildSolutionSharedEmail({
                        name: user.name,
                        ownerName: owner?.name || 'Someone',
                        role: user.role,
                        solutionName: card.name,
                        solutionId: card._id.toString(),
                    });
                    return sendEmail(
                        user.email,
                        `Solution "${card.name}" shared with you`,
                        html,
                        text
                    );
                })
            );

            results.forEach((result, index) => {
                if (result.status === 'fulfilled') {
                    emailsSent += 1;
                    return;
                }
                const failedUser = toNotify[index];
                const message = result.reason?.message || 'Unknown email error';
                console.error(`Share notification email failed for ${failedUser?.email}:`, message);
                emailErrors.push({ email: failedUser?.email, error: message });
            });
        }

        res.json({
            message: 'Solution sharing updated successfully',
            sharedWith: card.sharedWith,
            emailsSent,
            ...(emailErrors.length ? { emailErrors } : {}),
        });
        return;
    } catch (error) {
        next(error);
    }
};

// Soft delete solution card (only owner)
const deleteSolutionCard = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;

        // Only allow owner, disallow editors/viewers here explicitly by setting allowedRoles empty
        const { role, solutionCard } = await checkPermission({
            resourceType: 'solution',
            resourceId: id,
            userId,
            allowedRoles: [],  // no roles allowed except owner
            allowOwner: true,
        });

        if (role !== 'owner') {
            throw new ForbiddenError('Only the owner can delete this solution card');
        }

        if (solutionCard.isDeleted) {
            throw new NotFoundError('Solution card not found');
        }

        solutionCard.isDeleted = true;
        solutionCard.deletedAt = new Date();
        await solutionCard.save();

        res.json({ message: 'Solution card deleted (soft delete) successfully' });
    } catch (error) {
        next(error);
    }
};

// Restore a soft-deleted solution card (only owner)
const restoreSolutionCard = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;

        const card = await SolutionCard.findById(id);
        if (!card || !card.isDeleted) {
            throw new NotFoundError('Solution card not found or not deleted');
        }

        if (!card.owner.equals(userId)) {
            throw new ForbiddenError('Only owner can restore this solution card');
        }

        card.isDeleted = false;
        card.deletedAt = null;

        await card.save();

        res.json({ message: 'Solution card restored successfully', solutionCard: card });
    } catch (error) {
        next(error);
    }
};


module.exports = {
    createSolutionCard,
    getSolutionCards,
    getSolutionCardById,
    updateSolutionCard,
    deleteSolutionCard,
    restoreSolutionCard,
    getDeletedSolutionCards,
    shareSolutionCard
};
