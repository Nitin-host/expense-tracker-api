const { sendEmail } = require('./Email');
const { buildExpenseAddedEmail } = require('./emailTemplate');
const SolutionCard = require('../models/SolutionCard');
const User = require('../models/User');

async function notifyExpenseAdded({ expense, solutionCardId, addedByUserId }) {
    try {
        const card = await SolutionCard.findById(solutionCardId)
            .populate('owner', 'name email')
            .populate('sharedWith.user', 'name email');

        if (!card) return;

        const recipients = new Set();
        if (card.owner?.email && card.owner._id.toString() !== addedByUserId) {
            recipients.add(card.owner.email);
        }
        (card.sharedWith || []).forEach((s) => {
            if (s.user?.email && s.user._id.toString() !== addedByUserId) {
                recipients.add(s.user.email);
            }
        });

        if (!recipients.size) return;

        const addedBy = await User.findById(addedByUserId).select('name');
        const { html, text } = await buildExpenseAddedEmail({
            addedBy: addedBy?.name,
            solutionName: card.name,
            expenseName: expense.name,
            category: expense.category,
            amount: expense.amount,
            solutionId: card._id.toString(),
        });

        await Promise.all(
            [...recipients].map((email) =>
                sendEmail(email, `New expense in ${card.name}`, html, text)
            )
        );
    } catch (err) {
        console.error('Expense notification email failed:', err.message);
    }
}

module.exports = { notifyExpenseAdded };
