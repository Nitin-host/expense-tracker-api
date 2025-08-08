// controllers/collectController.js
const CollectedCash = require('../models/CollectedCash');
const { checkPermission } = require('../utils/checkPermission');

// Create Collected Cash (Owner + Editor only)
exports.createCollectedCash = async (req, res, next) => {
    try {
        const { solutionCardId, name, amount } = req.body;
        const userId = req.user.userId;

        if (!solutionCardId || !name || !amount) {
            return res.status(400).json({ message: 'solutionCardId, name, and amount are required.' });
        }

        // Permission check: create => Owner + Editor
        const { role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor'], // viewer is excluded
            allowOwner: true
        });

        // You can optionally set req.accessLevel if needed
        req.accessLevel = accessLevel;

        const collectedCash = await CollectedCash.create({
            solutionCardId,
            name,
            amount,
            user: userId,
        });

        res.status(201).json({ message: 'Collected cash added.', collectedCash, accessLevel });
    } catch (error) {
        next(error);
    }
};

// Get Collected Cash by Solution (Owner + Editor + Viewer)
exports.getCollectedCashBySolution = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;

        // Permission check: view => all roles
        const { role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor', 'viewer'],
            allowOwner: true
        });

        req.accessLevel = accessLevel;

        const collectedCash = await CollectedCash.find({ solutionCardId })
            .sort({ collectedDate: -1 });

        res.json({ collectedCash, accessLevel });
    } catch (error) {
        next(error);
    }
};

// Update Collected Cash (Owner + Editor only)
exports.updateCollectedCash = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { name, amount } = req.body;
        const userId = req.user.userId;

        // Permission check on the collected cash itself
        const { role: accessLevel } = await checkPermission({
            resourceType: 'collectedCash',
            resourceId: id,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true
        });

        req.accessLevel = accessLevel;

        const updated = await CollectedCash.findByIdAndUpdate(
            id,
            { name, amount, user: userId },
            { new: true }
        );

        if (!updated) return res.status(404).json({ message: 'Collected cash entry not found.' });

        res.json({ message: 'Collected cash updated.', collectedCash: updated, accessLevel });
    } catch (error) {
        next(error);
    }
};

// Delete Collected Cash (Owner + Editor only)
exports.deleteCollectedCash = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;

        // Permission check
        const { role: accessLevel } = await checkPermission({
            resourceType: 'collectedCash',
            resourceId: id,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true
        });

        req.accessLevel = accessLevel;

        const deleted = await CollectedCash.findByIdAndDelete(id);
        if (!deleted) return res.status(404).json({ message: 'Collected cash entry not found.' });

        res.json({ message: 'Collected cash entry deleted.', accessLevel });
    } catch (error) {
        next(error);
    }
};
