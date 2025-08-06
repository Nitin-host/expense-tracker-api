const SolutionCard = require('../models/SolutionCard');
const User = require('../models/User');
const { BadRequestError, NotFoundError, ForbiddenError } = require('../utils/Errors');

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

        // Find solution cards owned or shared with the user
        const cards = await SolutionCard.find({
            isDeleted: false,
            $or: [
                { owner: userId },
                { 'sharedWith.user': userId },
            ],
        })
            .sort({ year: -1 })
            // Populate sharedWith.user with name and email fields only
            .populate({
                path: 'sharedWith.user',
                select: 'name email'
            })
            .populate({
                path: 'owner',
                select: 'name email'
            });

        // Transform cards to structure sharedWith array with user info flat
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

        res.json(transformed);
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
        const { sharedWith, notifyUsers } = req.body; // sharedWith: [{ user, role}], e.g. from ShareSolutionModal
        const userId = req.user.userId;

        const card = await SolutionCard.findById(id);
        if (!card || card.isDeleted)
            throw new NotFoundError('Solution card not found');

        // Only owner can change sharing
        if (!card.owner.equals(userId)) {
            throw new ForbiddenError('Only owner can update this solution card sharing');
        }

        // Validate and enrich sharedWith (name/email/role)
        if (!Array.isArray(sharedWith)) {
            throw new BadRequestError('sharedWith must be an array');
        }
        const enriched = [];
        for (const item of sharedWith) {
            if (!item.user || !item.role) {
                throw new BadRequestError('Each sharedWith item must have user and role');
            }
            if (!['editor', 'viewer'].includes(item.role)) {
                throw new BadRequestError('Role must be either editor or viewer');
            }
            const user = await User.findById(item.user).select('name email');
            if (!user) throw new NotFoundError(`User ${item.user} not found`);
            enriched.push({
                user: user._id,
                name: user.name,
                email: user.email,
                role: item.role
            });
        }

        // Save the new sharedWith list
        card.sharedWith = enriched;
        await card.save();

        // Optional: send notifications to new users if notifyUsers == true

        res.json({ message: 'Solution sharing updated successfully', sharedWith: card.sharedWith });
    } catch (error) {
        next(error);
    }
};

// Soft delete solution card (only owner)
const deleteSolutionCard = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;
        const userRole = req.user.role; // assuming this is set in your auth middleware

        const card = await SolutionCard.findById(id);
        if (!card || card.isDeleted) {
            throw new NotFoundError('Solution card not found');
        }

        // Allow deletion if:
        // a) user is owner
        // b) OR user role is 'admin' or 'super_admin'
        const isOwner = card.owner.equals(userId);
        if (!isOwner && !['admin', 'super_admin'].includes(userRole)) {
            throw new ForbiddenError('Only owner, admin, or super_admin can delete this solution card');
        }

        card.isDeleted = true;
        card.deletedAt = new Date();

        await card.save();

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
