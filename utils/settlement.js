/**
 * Compute fair-share settlements for a solution.
 * Each participant's balance = (collected + paid on behalf) - fairShare of total expenses.
 */
function computeSettlements({ participants, expenses, collectedCash }) {
    const balances = {};

    participants.forEach((p) => {
        balances[p.id] = {
            userId: p.id,
            name: p.name,
            email: p.email,
            collected: 0,
            paid: 0,
            balance: 0,
        };
    });

    collectedCash.forEach((c) => {
        const uid = c.user?._id?.toString() || c.user?.toString();
        if (uid && balances[uid]) {
            balances[uid].collected += Number(c.amount) || 0;
        }
    });

    expenses.forEach((e) => {
        const uid = e.paidBy?._id?.toString() || e.paidBy?.toString();
        const paid = Number(e.advancePaid ?? e.amount) || 0;
        if (uid && balances[uid]) {
            balances[uid].paid += paid;
        }
    });

    const totalExpenses = expenses.reduce((s, e) => s + (Number(e.amount) || 0), 0);
    const count = participants.length || 1;
    const fairShare = totalExpenses / count;

    Object.values(balances).forEach((b) => {
        b.fairShare = fairShare;
        b.netContribution = b.collected + b.paid;
        b.balance = b.netContribution - fairShare;
    });

    const creditors = Object.values(balances)
        .filter((b) => b.balance > 0.01)
        .sort((a, b) => b.balance - a.balance);
    const debtors = Object.values(balances)
        .filter((b) => b.balance < -0.01)
        .sort((a, b) => a.balance - b.balance);

    const transfers = [];
    let i = 0;
    let j = 0;

    while (i < debtors.length && j < creditors.length) {
        const debtor = debtors[i];
        const creditor = creditors[j];
        const amount = Math.min(Math.abs(debtor.balance), creditor.balance);
        if (amount > 0.01) {
            transfers.push({
                from: { userId: debtor.userId, name: debtor.name, email: debtor.email },
                to: { userId: creditor.userId, name: creditor.name, email: creditor.email },
                amount: Math.round(amount * 100) / 100,
            });
            debtor.balance += amount;
            creditor.balance -= amount;
        }
        if (Math.abs(debtor.balance) < 0.01) i += 1;
        if (creditor.balance < 0.01) j += 1;
    }

    return {
        totalExpenses,
        fairSharePerPerson: Math.round(fairShare * 100) / 100,
        participantCount: count,
        balances: Object.values(balances).map((b) => ({
            ...b,
            balance: Math.round(b.balance * 100) / 100,
            collected: Math.round(b.collected * 100) / 100,
            paid: Math.round(b.paid * 100) / 100,
            fairShare: Math.round(b.fairShare * 100) / 100,
            netContribution: Math.round(b.netContribution * 100) / 100,
        })),
        suggestedTransfers: transfers,
    };
}

module.exports = { computeSettlements };
