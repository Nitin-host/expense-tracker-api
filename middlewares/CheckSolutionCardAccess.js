const SolutionCard = require('../models/SolutionCard');
const Expense = require('../models/Expense');
const { ForbiddenError, NotFoundError } = require('../utils/Errors');

async function checkSolutionCardAccess(req, res, next) {
    try {
        const userId = req.user.userId;

        // Safely get solutionCardId (may come from body, params, or expense object)
        let solutionCardId =
            (req.body && req.body.solutionCard) ||
            (req.params && req.params.solutionCardId) ||
            null;

        // Special case: If expenseId is present & solutionCardId is not found, look up expense and get solutionCard
        if (!solutionCardId && req.params && req.params.expenseId) {
            const expense = await Expense.findById(req.params.expenseId);
            if (!expense) return res.status(404).json({ message: 'Expense not found.' });
            solutionCardId = expense.solutionCard;
        }
        // Another fallback for update, delete based on ":id" param
        if (!solutionCardId && req.params && req.params.id) {
            const expense = await Expense.findById(req.params.id);
            if (!expense) return res.status(404).json({ message: 'Expense not found.' });
            solutionCardId = expense.solutionCard;
        }
        if (!solutionCardId) {
            return res.status(400).json({ message: 'solutionCard ID not found.' });
        }

        const card = await SolutionCard.findById(solutionCardId);
        if (!card || card.isDeleted) {
            return res.status(404).json({ message: 'Solution Card not found or deleted.' });
        }

        let role = null;
        if (card.owner.equals(userId)) {
            role = 'owner';
        } else {
            const sharedUser = card.sharedWith.find(su => su.user.equals(userId));
            if (sharedUser) role = sharedUser.role;
        }

        if (!role) {
            return res.status(403).json({ message: 'Access denied to this Solution Card' });
        }

        req.solutionCard = card;
        req.solutionCardRole = role;
        next();
    } catch (err) {
        next(err);
    }
}

module.exports = checkSolutionCardAccess;
