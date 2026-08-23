// utils/checkPermission.js
const SolutionCard = require('../models/SolutionCard');
const CollectedCash = require('../models/CollectedCash');
const Expense = require('../models/Expense');

const solutionSelect = 'owner sharedWith';

async function loadSolutionCard(id) {
    return SolutionCard.findById(id).select(solutionSelect).lean();
}

async function checkPermission({ resourceType, resourceId, userId, allowedRoles = [], allowOwner = true }) {
    let solutionCard;
    let resource;

    switch (resourceType) {
        case 'solution':
            solutionCard = await loadSolutionCard(resourceId);
            if (!solutionCard) throw makeError('Solution not found.', 404);
            resource = solutionCard;
            break;

        case 'collectedCash':
            resource = await CollectedCash.findById(resourceId).select('solutionCardId').lean();
            if (!resource) throw makeError('Collected cash entry not found.', 404);
            solutionCard = await loadSolutionCard(resource.solutionCardId);
            break;

        case 'expense':
            // Need full payments (urls + publicIds) for update/delete Cloudinary cleanup
            resource = await Expense.findById(resourceId).populate('solutionCard');
            if (!resource) throw makeError('Expense not found.', 404);
            solutionCard = resource.solutionCard;
            break;

        default:
            throw makeError('Invalid resource type.', 400);
    }

    if (!solutionCard) throw makeError('Linked solution card not found.', 404);

    const userIdStr = userId.toString();

    if (allowOwner && solutionCard.owner.toString() === userIdStr) {
        return { role: 'owner', resource, solutionCard };
    }

    const sharedUser = (solutionCard.sharedWith || []).find(
        (su) => su.user.toString() === userIdStr
    );
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
