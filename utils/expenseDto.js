/**
 * Strip sensitive / heavy fields from expense documents for list responses.
 */
function toLeanExpense(expense) {
    const obj = typeof expense.toObject === 'function' ? expense.toObject() : { ...expense };
    const payments = Array.isArray(obj.payments) ? obj.payments : [];
    const paymentMethods = [...new Set(payments.map((p) => p.paymentMethod).filter(Boolean))];
    let screenshotCount = 0;
    payments.forEach((p) => {
        // List queries may omit URLs for payload size; count publicIds as a fallback.
        if (Array.isArray(p.upiScreenshotUrls) && p.upiScreenshotUrls.length) {
            screenshotCount += p.upiScreenshotUrls.length;
        } else if (Array.isArray(p.upiScreenshotPublicIds) && p.upiScreenshotPublicIds.length) {
            screenshotCount += p.upiScreenshotPublicIds.length;
        }
    });

    const paidBy =
        obj.paidBy && typeof obj.paidBy === 'object'
            ? { _id: obj.paidBy._id, name: obj.paidBy.name, email: obj.paidBy.email }
            : obj.paidBy;

    // Keep amounts/methods/dates for list UI (no screenshot URLs — those load on detail view)
    const paymentHistory = payments.map((p) => ({
        paidAmount: Number(p.paidAmount) || 0,
        paymentMethod: p.paymentMethod || 'cash',
        paidAt: p.paidAt || null,
        hasScreenshots:
            (Array.isArray(p.upiScreenshotUrls) && p.upiScreenshotUrls.length > 0) ||
            (Array.isArray(p.upiScreenshotPublicIds) && p.upiScreenshotPublicIds.length > 0),
    }));

    return {
        _id: obj._id,
        name: obj.name,
        category: obj.category,
        amount: obj.amount,
        advancePaid: obj.advancePaid,
        pendingAmount: obj.pendingAmount,
        paymentStatus: obj.paymentStatus,
        paidBy,
        paymentMethods,
        paymentHistory,
        hasScreenshots: screenshotCount > 0,
        screenshotCount,
        createdAt: obj.createdAt,
        updatedAt: obj.updatedAt,
        solutionCard: obj.solutionCard,
        // Keep a minimal payments stub for table columns that read payments.paymentMethod
        payments: paymentMethods.map((paymentMethod) => ({ paymentMethod })),
    };
}

/**
 * Remove Cloudinary public IDs from full expense payloads (client never needs them).
 */
function sanitizeExpenseForClient(expense) {
    const obj = typeof expense.toObject === 'function' ? expense.toObject() : { ...expense };
    if (Array.isArray(obj.payments)) {
        obj.payments = obj.payments.map((p) => {
            const { upiScreenshotPublicIds, ...rest } = p;
            return rest;
        });
    }
    return obj;
}

module.exports = { toLeanExpense, sanitizeExpenseForClient };
