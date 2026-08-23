const mongoose = require('mongoose');
const Expense = require('../models/Expense');
const CollectedCash = require('../models/CollectedCash');
const SolutionCard = require('../models/SolutionCard');
const User = require('../models/User');
const { checkPermission } = require('../utils/checkPermission');
const { BadRequestError } = require('../utils/Errors');
const { toLeanExpense } = require('../utils/expenseDto');

function monthRange(year, month) {
    const start = new Date(year, month - 1, 1);
    const end = new Date(year, month, 0, 23, 59, 59, 999);
    return { start, end };
}

function yearRange(year) {
    return {
        start: new Date(year, 0, 1),
        end: new Date(year, 11, 31, 23, 59, 59, 999),
    };
}

/** Local calendar day bounds for YYYY-MM-DD (server local timezone). */
function dayRange(dateStr) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(dateStr || '').trim());
    if (!match) return null;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    if (!year || month < 1 || month > 12 || day < 1 || day > 31) return null;
    const start = new Date(year, month - 1, day, 0, 0, 0, 0);
    const end = new Date(year, month - 1, day, 23, 59, 59, 999);
    if (Number.isNaN(start.getTime()) || start.getDate() !== day) return null;
    return { start, end, date: `${match[1]}-${match[2]}-${match[3]}` };
}

function todayDateParam() {
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, '0');
    const d = String(now.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

function summarizeMethodRows(rows) {
    const byMethod = { cash: 0, upi: 0 };
    let cashCount = 0;
    let upiCount = 0;
    for (const row of rows) {
        const method = String(row._id || 'cash').toLowerCase();
        const amount = Number(row.amount) || 0;
        const count = Number(row.count) || 0;
        if (method === 'upi') {
            byMethod.upi = amount;
            upiCount = count;
        } else {
            byMethod.cash += amount;
            cashCount += count;
        }
    }
    return {
        cash: byMethod.cash,
        upi: byMethod.upi,
        total: byMethod.cash + byMethod.upi,
        cashCount,
        upiCount,
        count: cashCount + upiCount,
    };
}

function formatDate(val) {
    if (!val) return '';
    const d = val instanceof Date ? val : new Date(val);
    return Number.isNaN(d.getTime()) ? String(val) : d.toLocaleString('en-IN', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatDateShort(val) {
    if (!val) return '';
    const d = val instanceof Date ? val : new Date(val);
    return Number.isNaN(d.getTime()) ? String(val) : d.toLocaleDateString('en-IN', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
    });
}

function formatPaymentStatus(status) {
    const labels = {
        pending: 'Pending',
        partially_paid: 'Partially paid',
        fully_paid: 'Fully paid',
    };
    return labels[status] || status || '';
}

function buildPeriodLabel(applyPeriod, year, month) {
    if (!applyPeriod) return 'All time';
    if (month) {
        return `${new Date(year, month - 1).toLocaleString('en-IN', { month: 'long' })} ${year}`;
    }
    return String(year);
}

const EXPORT_ROW_LIMIT = 5000;

const EXPORT_TITLES = {
    summary: 'Financial Summary Report',
    expenses: 'Expense Details Report',
    'collected-cash': 'Collected Cash Report',
    daily: 'Daily Report',
};

function withExportCap(query, limit = EXPORT_ROW_LIMIT) {
    return query.limit(limit);
}

function buildExportPayload({ type, solutionName, periodLabel, sections }) {
    return {
        document: {
            title: EXPORT_TITLES[type] || 'Report',
            solutionName,
            period: periodLabel,
            generatedAt: new Date().toISOString(),
            type,
            appName: 'Expense Tracker',
        },
        sections,
    };
}

function buildPeriodFilters(year, month, solutionObjectId) {
    const expenseFilter = {
        solutionCard: solutionObjectId,
        isDeleted: { $ne: true },
    };
    const cashFilter = { solutionCardId: solutionObjectId };

    if (month) {
        const { start, end } = monthRange(year, month);
        expenseFilter.createdAt = { $gte: start, $lte: end };
        cashFilter.collectedDate = { $gte: start, $lte: end };
    } else {
        const { start, end } = yearRange(year);
        expenseFilter.createdAt = { $gte: start, $lte: end };
        cashFilter.collectedDate = { $gte: start, $lte: end };
    }

    return { expenseFilter, cashFilter };
}

exports.getReports = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;
        const year = parseInt(req.query.year, 10) || new Date().getFullYear();
        const month = req.query.month ? parseInt(req.query.month, 10) : null;

        if (!mongoose.Types.ObjectId.isValid(solutionCardId)) {
            throw new BadRequestError('Invalid solutionCardId');
        }

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true,
        });

        const solutionObjectId = new mongoose.Types.ObjectId(solutionCardId);
        const { expenseFilter, cashFilter } = buildPeriodFilters(year, month, solutionObjectId);

        const { start: yearStart, end: yearEnd } = yearRange(year);
        const monthlyExpenseMatch = {
            solutionCard: solutionObjectId,
            isDeleted: { $ne: true },
            createdAt: { $gte: yearStart, $lte: yearEnd },
        };

        const [expenseTotals, cashTotals, paidByAgg, monthlyBreakdown] = await Promise.all([
            Expense.aggregate([
                { $match: expenseFilter },
                {
                    $group: {
                        _id: null,
                        totalExpenses: { $sum: '$amount' },
                        expenseCount: { $sum: 1 },
                    },
                },
            ]),
            CollectedCash.aggregate([
                { $match: cashFilter },
                {
                    $group: {
                        _id: null,
                        totalCollected: { $sum: '$amount' },
                        cashCount: { $sum: 1 },
                    },
                },
            ]),
            Expense.aggregate([
                { $match: expenseFilter },
                { $match: { paidBy: { $ne: null } } },
                {
                    $group: {
                        _id: '$paidBy',
                        totalPaid: { $sum: '$advancePaid' },
                        count: { $sum: 1 },
                    },
                },
            ]),
            Expense.aggregate([
                { $match: monthlyExpenseMatch },
                {
                    $group: {
                        _id: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } },
                        total: { $sum: '$amount' },
                    },
                },
                { $sort: { '_id.year': 1, '_id.month': 1 } },
            ]),
        ]);

        const userIds = paidByAgg.map((p) => p._id).filter(Boolean);
        const users = await User.find({ _id: { $in: userIds } }).select('name email').lean();
        const userMap = Object.fromEntries(users.map((u) => [u._id.toString(), u]));

        const whoPaidWhat = paidByAgg.map((p) => {
            const id = p._id?.toString();
            return {
                userId: id,
                name: userMap[id]?.name || 'Unknown',
                email: userMap[id]?.email || '',
                totalPaid: p.totalPaid || 0,
                expenseCount: p.count || 0,
            };
        });

        const totalExpenses = expenseTotals[0]?.totalExpenses || 0;
        const totalCollected = cashTotals[0]?.totalCollected || 0;

        res.json({
            year,
            month,
            totalExpenses,
            totalCollected,
            remaining: totalCollected - totalExpenses,
            whoPaidWhat,
            monthlyBreakdown: monthlyBreakdown.map((m) => ({
                year: m._id.year,
                month: m._id.month,
                total: m.total,
            })),
            expenseCount: expenseTotals[0]?.expenseCount || 0,
            cashCount: cashTotals[0]?.cashCount || 0,
        });
    } catch (error) {
        next(error);
    }
};

exports.getDailyReport = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const userId = req.user.userId;
        const dateParam = req.query.date || todayDateParam();
        const range = dayRange(dateParam);

        if (!mongoose.Types.ObjectId.isValid(solutionCardId)) {
            throw new BadRequestError('Invalid solutionCardId');
        }
        if (!range) {
            throw new BadRequestError('Invalid date. Use YYYY-MM-DD.');
        }

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true,
        });

        const solutionObjectId = new mongoose.Types.ObjectId(solutionCardId);
        const expenseMatch = { solutionCard: solutionObjectId, isDeleted: { $ne: true } };
        const { start, end, date } = range;

        const [
            paymentDayAgg,
            collectedByMethod,
            collectedEntries,
            overallCollectedAgg,
            overallExpenseAgg,
        ] = await Promise.all([
            Expense.aggregate([
                { $match: expenseMatch },
                { $unwind: { path: '$payments', preserveNullAndEmptyArrays: false } },
                {
                    $match: {
                        'payments.paidAt': { $gte: start, $lte: end },
                    },
                },
                {
                    $facet: {
                        byMethod: [
                            {
                                $group: {
                                    _id: { $ifNull: ['$payments.paymentMethod', 'cash'] },
                                    amount: { $sum: '$payments.paidAmount' },
                                    count: { $sum: 1 },
                                },
                            },
                        ],
                        rows: [
                            {
                                $project: {
                                    expenseId: '$_id',
                                    expenseName: '$name',
                                    category: '$category',
                                    paidAmount: '$payments.paidAmount',
                                    paymentMethod: '$payments.paymentMethod',
                                    paidAt: '$payments.paidAt',
                                },
                            },
                            { $sort: { paidAt: -1 } },
                        ],
                    },
                },
            ]),
            CollectedCash.aggregate([
                {
                    $match: {
                        solutionCardId: solutionObjectId,
                        collectedDate: { $gte: start, $lte: end },
                    },
                },
                {
                    $group: {
                        _id: { $ifNull: ['$paymentMethod', 'cash'] },
                        amount: { $sum: '$amount' },
                        count: { $sum: 1 },
                    },
                },
            ]),
            CollectedCash.find({
                solutionCardId: solutionObjectId,
                collectedDate: { $gte: start, $lte: end },
            })
                .sort({ collectedDate: -1 })
                .select('name amount paymentMethod collectedDate')
                .lean(),
            CollectedCash.aggregate([
                { $match: { solutionCardId: solutionObjectId } },
                { $group: { _id: null, total: { $sum: '$amount' } } },
            ]),
            Expense.aggregate([
                { $match: expenseMatch },
                { $group: { _id: null, total: { $sum: '$amount' } } },
            ]),
        ]);

        const paymentDayFacet = paymentDayAgg[0] || { byMethod: [], rows: [] };
        const spentByMethod = paymentDayFacet.byMethod;
        const paymentRows = paymentDayFacet.rows;

        const collected = summarizeMethodRows(collectedByMethod);
        const spent = summarizeMethodRows(spentByMethod);
        const dayRemaining = collected.total - spent.total;
        const overallCollected = overallCollectedAgg[0]?.total || 0;
        const overallExpenses = overallExpenseAgg[0]?.total || 0;
        const overallRemaining = overallCollected - overallExpenses;

        res.json({
            date,
            collected: {
                total: collected.total,
                cash: collected.cash,
                upi: collected.upi,
                count: collected.count,
            },
            spent: {
                total: spent.total,
                cash: spent.cash,
                upi: spent.upi,
                count: spent.count,
            },
            dayRemaining,
            overall: {
                collected: overallCollected,
                expenses: overallExpenses,
                remaining: overallRemaining,
            },
            collectedEntries: collectedEntries.map((c) => ({
                id: c._id,
                name: c.name,
                amount: c.amount,
                paymentMethod: c.paymentMethod || 'cash',
                date: c.collectedDate,
            })),
            payments: paymentRows.map((p) => ({
                expenseId: p.expenseId,
                expenseName: p.expenseName,
                category: p.category,
                paidAmount: p.paidAmount,
                paymentMethod: p.paymentMethod || 'cash',
                paidAt: p.paidAt,
            })),
        });
    } catch (error) {
        next(error);
    }
};

exports.exportData = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const { type = 'expenses' } = req.query;
        const userId = req.user.userId;
        const applyPeriod = req.query.year != null || req.query.month != null;
        const year = parseInt(req.query.year, 10) || new Date().getFullYear();
        const month = req.query.month ? parseInt(req.query.month, 10) : null;

        if (!mongoose.Types.ObjectId.isValid(solutionCardId)) {
            throw new BadRequestError('Invalid solutionCardId');
        }

        await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true,
        });

        const solutionObjectId = new mongoose.Types.ObjectId(solutionCardId);
        const solutionCard = await SolutionCard.findById(solutionObjectId).select('name year').lean();
        const solutionName = solutionCard?.name || 'Solution';
        const periodLabel = buildPeriodLabel(applyPeriod, year, month);

        const expenseFilter = {
            solutionCard: solutionObjectId,
            isDeleted: { $ne: true },
        };
        const cashFilter = { solutionCardId: solutionObjectId };

        if (applyPeriod) {
            const periodFilters = buildPeriodFilters(year, month, solutionObjectId);
            Object.assign(expenseFilter, periodFilters.expenseFilter);
            Object.assign(cashFilter, periodFilters.cashFilter);
        }

        if (type === 'daily') {
            const dateParam = req.query.date || todayDateParam();
            const range = dayRange(dateParam);
            if (!range) {
                throw new BadRequestError('Invalid date. Use YYYY-MM-DD.');
            }

            const { start, end, date } = range;
            const expenseMatch = {
                solutionCard: solutionObjectId,
                isDeleted: { $ne: true },
            };

            const [
                collectedByMethod,
                spentByMethod,
                collectedEntries,
                paymentRows,
                overallCollectedAgg,
                overallExpenseAgg,
            ] = await Promise.all([
                CollectedCash.aggregate([
                    {
                        $match: {
                            solutionCardId: solutionObjectId,
                            collectedDate: { $gte: start, $lte: end },
                        },
                    },
                    {
                        $group: {
                            _id: { $ifNull: ['$paymentMethod', 'cash'] },
                            amount: { $sum: '$amount' },
                            count: { $sum: 1 },
                        },
                    },
                ]),
                Expense.aggregate([
                    { $match: expenseMatch },
                    { $unwind: { path: '$payments', preserveNullAndEmptyArrays: false } },
                    { $match: { 'payments.paidAt': { $gte: start, $lte: end } } },
                    {
                        $group: {
                            _id: { $ifNull: ['$payments.paymentMethod', 'cash'] },
                            amount: { $sum: '$payments.paidAmount' },
                            count: { $sum: 1 },
                        },
                    },
                ]),
                CollectedCash.find({
                    solutionCardId: solutionObjectId,
                    collectedDate: { $gte: start, $lte: end },
                })
                    .sort({ collectedDate: -1 })
                    .lean(),
                Expense.aggregate([
                    { $match: expenseMatch },
                    { $unwind: { path: '$payments', preserveNullAndEmptyArrays: false } },
                    { $match: { 'payments.paidAt': { $gte: start, $lte: end } } },
                    {
                        $project: {
                            expenseName: '$name',
                            category: '$category',
                            paidAmount: '$payments.paidAmount',
                            paymentMethod: '$payments.paymentMethod',
                            paidAt: '$payments.paidAt',
                        },
                    },
                    { $sort: { paidAt: -1 } },
                ]),
                CollectedCash.aggregate([
                    { $match: { solutionCardId: solutionObjectId } },
                    { $group: { _id: null, total: { $sum: '$amount' } } },
                ]),
                Expense.aggregate([
                    { $match: expenseMatch },
                    { $group: { _id: null, total: { $sum: '$amount' } } },
                ]),
            ]);

            const collected = summarizeMethodRows(collectedByMethod);
            const spent = summarizeMethodRows(spentByMethod);
            const dayRemaining = collected.total - spent.total;
            const overallCollected = overallCollectedAgg[0]?.total || 0;
            const overallExpenses = overallExpenseAgg[0]?.total || 0;
            const overallRemaining = overallCollected - overallExpenses;

            return res.json(
                buildExportPayload({
                    type: 'daily',
                    solutionName,
                    periodLabel: formatDateShort(start),
                    sections: [
                        {
                            id: 'daily-stats',
                            title: `Daily snapshot · ${date}`,
                            kind: 'stats',
                            items: [
                                {
                                    label: 'Collected today',
                                    value: collected.total,
                                    format: 'currency',
                                    tone: 'success',
                                },
                                {
                                    label: 'Spent today',
                                    value: spent.total,
                                    format: 'currency',
                                    tone: 'warning',
                                },
                                {
                                    label: 'Left today',
                                    value: dayRemaining,
                                    format: 'currency',
                                    tone: dayRemaining < 0 ? 'danger' : 'success',
                                },
                                {
                                    label: 'Overall wallet left',
                                    value: overallRemaining,
                                    format: 'currency',
                                    tone: overallRemaining < 0 ? 'danger' : 'success',
                                },
                                { label: 'Collected via cash', value: collected.cash, format: 'currency' },
                                { label: 'Collected via UPI', value: collected.upi, format: 'currency' },
                                { label: 'Spent via cash', value: spent.cash, format: 'currency' },
                                { label: 'Spent via UPI', value: spent.upi, format: 'currency' },
                            ],
                        },
                        {
                            id: 'daily-collected',
                            title: 'Collected today',
                            kind: 'table',
                            headers: ['Contributor', 'Amount (₹)', 'Method'],
                            rows: collectedEntries.map((c) => [
                                c.name,
                                c.amount,
                                String(c.paymentMethod || 'cash').toUpperCase(),
                            ]),
                            columnFormats: ['text', 'currency', 'text'],
                            columnAlign: ['left', 'right', 'left'],
                        },
                        {
                            id: 'daily-spent',
                            title: 'Spent today',
                            kind: 'table',
                            headers: ['Expense', 'Category', 'Paid (₹)', 'Method'],
                            rows: paymentRows.map((p) => [
                                p.expenseName,
                                p.category,
                                p.paidAmount,
                                String(p.paymentMethod || 'cash').toUpperCase(),
                            ]),
                            columnFormats: ['text', 'text', 'currency', 'text'],
                            columnAlign: ['left', 'left', 'right', 'left'],
                        },
                    ],
                })
            );
        }

        if (type === 'summary') {
            const [expenseTotals, cashTotals, paidByAgg, monthlyBreakdown] = await Promise.all([
                Expense.aggregate([
                    { $match: expenseFilter },
                    {
                        $group: {
                            _id: null,
                            totalExpenses: { $sum: '$amount' },
                            expenseCount: { $sum: 1 },
                        },
                    },
                ]),
                CollectedCash.aggregate([
                    { $match: cashFilter },
                    {
                        $group: {
                            _id: null,
                            totalCollected: { $sum: '$amount' },
                            cashCount: { $sum: 1 },
                        },
                    },
                ]),
                Expense.aggregate([
                    { $match: expenseFilter },
                    { $match: { paidBy: { $ne: null } } },
                    {
                        $group: {
                            _id: '$paidBy',
                            totalPaid: { $sum: '$advancePaid' },
                            count: { $sum: 1 },
                        },
                    },
                ]),
                Expense.aggregate([
                    {
                        $match: applyPeriod
                            ? buildPeriodFilters(year, null, solutionObjectId).expenseFilter
                            : { solutionCard: solutionObjectId, isDeleted: { $ne: true } },
                    },
                    {
                        $group: {
                            _id: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } },
                            total: { $sum: '$amount' },
                        },
                    },
                    { $sort: { '_id.year': 1, '_id.month': 1 } },
                ]),
            ]);

            const userIds = paidByAgg.map((p) => p._id).filter(Boolean);
            const users = await User.find({ _id: { $in: userIds } }).select('name email').lean();
            const userMap = Object.fromEntries(users.map((u) => [u._id.toString(), u]));

            const totalExpenses = expenseTotals[0]?.totalExpenses || 0;
            const totalCollected = cashTotals[0]?.totalCollected || 0;
            const remaining = totalCollected - totalExpenses;
            const expenseCount = expenseTotals[0]?.expenseCount || 0;
            const cashCount = cashTotals[0]?.cashCount || 0;

            const whoPaidRows = paidByAgg.map((p) => {
                const id = p._id?.toString();
                return [
                    userMap[id]?.name || 'Unknown',
                    userMap[id]?.email || '—',
                    p.totalPaid || 0,
                    p.count || 0,
                ];
            });

            const monthlyRows = monthlyBreakdown.map((m) => [
                new Date(m._id.year, m._id.month - 1).toLocaleString('en-IN', {
                    month: 'long',
                    year: 'numeric',
                }),
                m.total,
            ]);

            const sections = [
                {
                    id: 'overview',
                    title: 'Overview',
                    kind: 'stats',
                    items: [
                        { label: 'Total collected', value: totalCollected, format: 'currency', tone: 'success' },
                        { label: 'Total expenses', value: totalExpenses, format: 'currency', tone: 'warning' },
                        {
                            label: 'Remaining balance',
                            value: remaining,
                            format: 'currency',
                            tone: remaining < 0 ? 'danger' : 'success',
                        },
                        { label: 'Expense entries', value: expenseCount, format: 'number' },
                        { label: 'Cash entries', value: cashCount, format: 'number' },
                    ],
                },
            ];

            if (whoPaidRows.length) {
                sections.push({
                    id: 'who-paid',
                    title: 'Who paid what',
                    description: 'Breakdown by person for the selected period.',
                    kind: 'table',
                    headers: ['Name', 'Email', 'Total paid (₹)', 'No. of expenses'],
                    rows: whoPaidRows,
                    columnFormats: ['text', 'text', 'currency', 'number'],
                    columnAlign: ['left', 'left', 'right', 'right'],
                });
            }

            if (monthlyRows.length) {
                sections.push({
                    id: 'monthly-trend',
                    title: 'Monthly expense trend',
                    description: 'Total expenses recorded each month.',
                    kind: 'table',
                    headers: ['Month', 'Total expenses (₹)'],
                    rows: monthlyRows,
                    columnFormats: ['text', 'currency'],
                    columnAlign: ['left', 'right'],
                });
            }

            return res.json(buildExportPayload({ type, solutionName, periodLabel, sections }));
        }

        if (type === 'collected-cash') {
            const entries = await withExportCap(
                CollectedCash.find(cashFilter).sort({ collectedDate: -1 }).lean()
            );
            const totalCollected = entries.reduce((s, c) => s + (Number(c.amount) || 0), 0);
            const truncated = entries.length >= EXPORT_ROW_LIMIT;

            const cashViaCash = entries
                .filter((r) => String(r.paymentMethod || 'cash').toLowerCase() !== 'upi')
                .reduce((s, c) => s + (Number(c.amount) || 0), 0);
            const cashViaUpi = entries
                .filter((r) => String(r.paymentMethod || '').toLowerCase() === 'upi')
                .reduce((s, c) => s + (Number(c.amount) || 0), 0);

            const tableRows = entries.map((r) => [
                r.name,
                r.amount,
                String(r.paymentMethod || 'cash').toUpperCase(),
                formatDateShort(r.collectedDate),
                formatDateShort(r.updatedDate),
            ]);

            return res.json(
                buildExportPayload({
                    type,
                    solutionName,
                    periodLabel,
                    sections: [
                        {
                            id: 'cash-stats',
                            title: 'Summary',
                            kind: 'stats',
                            items: [
                                { label: 'Total collected', value: totalCollected, format: 'currency', tone: 'success' },
                                { label: 'Via cash', value: cashViaCash, format: 'currency', tone: 'success' },
                                { label: 'Via UPI', value: cashViaUpi, format: 'currency' },
                                { label: 'Entries', value: entries.length, format: 'number' },
                                ...(truncated
                                    ? [{ label: 'Note', value: `Limited to latest ${EXPORT_ROW_LIMIT} rows`, format: 'text' }]
                                    : []),
                            ],
                        },
                        {
                            id: 'cash-list',
                            title: 'Collected cash entries',
                            description: truncated
                                ? `Latest ${EXPORT_ROW_LIMIT} contributions for this solution.`
                                : 'Each contribution recorded for this solution.',
                            kind: 'table',
                            headers: ['Contributor', 'Amount (₹)', 'Method', 'Collected on', 'Last updated'],
                            rows: tableRows,
                            columnFormats: ['text', 'currency', 'text', 'text', 'text'],
                            columnAlign: ['left', 'right', 'left', 'left', 'left'],
                        },
                    ],
                })
            );
        }

        const expenses = await withExportCap(
            Expense.find(expenseFilter)
                .populate('paidBy', 'name email')
                .sort({ createdAt: -1 })
                .lean()
        );
        const truncated = expenses.length >= EXPORT_ROW_LIMIT;

        const totalAmount = expenses.reduce((s, e) => s + (Number(e.amount) || 0), 0);
        const totalPaid = expenses.reduce((s, e) => s + (Number(e.advancePaid) || 0), 0);
        const totalPending = expenses.reduce((s, e) => s + (Number(e.pendingAmount) || 0), 0);
        let expenseCashPaid = 0;
        let expenseUpiPaid = 0;
        expenses.forEach((e) => {
            (e.payments || []).forEach((p) => {
                const amt = Number(p.paidAmount) || 0;
                if (String(p.paymentMethod || '').toLowerCase() === 'upi') expenseUpiPaid += amt;
                else expenseCashPaid += amt;
            });
        });

        const tableRows = expenses.map((e) => {
            const lean = toLeanExpense(e);
            const methods = (lean.paymentMethods || [])
                .map((m) => String(m).toUpperCase())
                .join(', ');
            return [
                lean.name,
                lean.category,
                lean.amount,
                lean.advancePaid,
                lean.pendingAmount,
                methods || '—',
                formatPaymentStatus(lean.paymentStatus),
                lean.paidBy?.name || '—',
                formatDateShort(lean.createdAt),
            ];
        });

        res.json(
            buildExportPayload({
                type: 'expenses',
                solutionName,
                periodLabel,
                sections: [
                    {
                        id: 'expense-stats',
                        title: 'Summary',
                        kind: 'stats',
                        items: [
                            { label: 'Total bill amount', value: totalAmount, format: 'currency', tone: 'warning' },
                            { label: 'Amount paid', value: totalPaid, format: 'currency', tone: 'success' },
                            { label: 'Paid via cash', value: expenseCashPaid, format: 'currency', tone: 'success' },
                            { label: 'Paid via UPI', value: expenseUpiPaid, format: 'currency' },
                            { label: 'Pending', value: totalPending, format: 'currency', tone: 'danger' },
                            { label: 'Entries', value: expenses.length, format: 'number' },
                            ...(truncated
                                ? [{ label: 'Note', value: `Limited to latest ${EXPORT_ROW_LIMIT} rows`, format: 'text' }]
                                : []),
                        ],
                    },
                    {
                        id: 'expense-list',
                        title: 'Expense line items',
                        description: truncated
                            ? `Latest ${EXPORT_ROW_LIMIT} expenses in this period.`
                            : 'Detailed list of all expenses in this period.',
                        kind: 'table',
                        headers: [
                            'Expense name',
                            'Category',
                            'Bill (₹)',
                            'Paid (₹)',
                            'Pending (₹)',
                            'Method',
                            'Status',
                            'Paid by',
                            'Date',
                        ],
                        rows: tableRows,
                        columnFormats: [
                            'text',
                            'text',
                            'currency',
                            'currency',
                            'currency',
                            'text',
                            'text',
                            'text',
                            'text',
                        ],
                        columnAlign: [
                            'left',
                            'left',
                            'right',
                            'right',
                            'right',
                            'left',
                            'left',
                            'left',
                            'left',
                        ],
                    },
                ],
            })
        );
    } catch (error) {
        next(error);
    }
};
