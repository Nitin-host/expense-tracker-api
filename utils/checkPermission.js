// utils/checkPermission.js
const SolutionCard = require('../models/SolutionCard');
const CollectedCash = require('../models/CollectedCash');
const Expense = require('../models/Expense');

async function checkPermission({ resourceType, resourceId, userId, allowedRoles = [], allowOwner = true }) {
    let solutionCard;
    let resource;

    switch (resourceType) {
        case 'solution':
            solutionCard = await SolutionCard.findById(resourceId);
            if (!solutionCard) throw makeError('Solution not found.', 404);
            resource = solutionCard;
            break;

        case 'collectedCash':
            resource = await CollectedCash.findById(resourceId).populate('solutionCardId');
            if (!resource) throw makeError('Collected cash entry not found.', 404);
            solutionCard = resource.solutionCardId;
            break;

        case 'expense':
            resource = await Expense.findById(resourceId).populate('solutionCard');
            if (!resource) throw makeError('Expense not found.', 404);
            solutionCard = resource.solutionCard;
            break;

        default:
            throw makeError('Invalid resource type.', 400);
    }

    if (!solutionCard) throw makeError('Linked solution card not found.', 404);

    // Owner check
    if (allowOwner && solutionCard.owner.toString() === userId.toString()) {
        return { role: 'owner', resource, solutionCard };
    }

    // Shared user role check
    const sharedUser = solutionCard.sharedWith.find(su => su.user.toString() === userId.toString());
    if (!sharedUser) throw makeError('Access denied.', 403);

    if (!allowedRoles.includes(sharedUser.role)) {
        throw makeError('Insufficient permissions.', 403);
    }

    return { role: sharedUser.role, resource, solutionCard };
}

function makeError(message, statusCode) {
    const err = new Error(message);
    err.statusCode = statusCode;
    return err;
}

module.exports = { checkPermission };
