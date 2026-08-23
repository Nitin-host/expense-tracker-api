const { sendEmail } = require('./Email');
const { buildExpenseAddedEmail } = require('./emailTemplate');
const SolutionCard = require('../models/SolutionCard');
const User = require('../models/User');

function normalizeId(value) {
    if (value == null) return '';
    if (typeof value === 'object' && value._id != null) return String(value._id);
    return String(value);
}

function collectRecipientEmails(card, excludeUserId) {
    const exclude = normalizeId(excludeUserId);
    const recipients = new Set();

    const ownerEmail = card.owner?.email;
    const ownerId = normalizeId(card.owner);
    if (ownerEmail && ownerId && ownerId !== exclude) {
        recipients.add(String(ownerEmail).trim().toLowerCase());
    }

    (card.sharedWith || []).forEach((share) => {
        const userId = normalizeId(share.user);
        // Prefer live user email; fall back to denormalized share.email
        const email = share.user?.email || share.email;
        if (!email || !userId || userId === exclude) return;
        recipients.add(String(email).trim().toLowerCase());
    });

    return [...recipients].filter(Boolean);
}

async function notifyExpenseAdded({ expense, solutionCardId, addedByUserId }) {
    try {
        const card = await SolutionCard.findById(solutionCardId)
            .populate('owner', 'name email')
            .populate('sharedWith.user', 'name email');

        if (!card) return { emailsSent: 0 };

        const recipients = collectRecipientEmails(card, addedByUserId);
        if (!recipients.length) {
            console.log(`[Email] Expense notify skipped — no recipients for solution ${solutionCardId}`);
            return { emailsSent: 0 };
        }

        const addedBy = await User.findById(addedByUserId).select('name');
        const { html, text } = await buildExpenseAddedEmail({
            addedBy: addedBy?.name,
            solutionName: card.name,
            expenseName: expense.name,
            category: expense.category,
            amount: expense.amount,
            solutionId: card._id.toString(),
        });

        const results = await Promise.allSettled(
            recipients.map((email) =>
                sendEmail(email, `New expense in ${card.name}`, html, text)
            )
        );

        let emailsSent = 0;
        results.forEach((result, index) => {
            if (result.status === 'fulfilled') {
                emailsSent += 1;
                return;
            }
            console.error(
                `Expense notification email failed for ${recipients[index]}:`,
                result.reason?.message || result.reason
            );
        });

        console.log(
            `[Email] Expense notify for "${card.name}": ${emailsSent}/${recipients.length} sent`
        );
        return { emailsSent, attempted: recipients.length };
    } catch (err) {
        console.error('Expense notification email failed:', err.message);
        return { emailsSent: 0, error: err.message };
    }
}

module.exports = { notifyExpenseAdded, collectRecipientEmails };
