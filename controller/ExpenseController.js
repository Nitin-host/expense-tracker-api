// controllers/expenseController.js
const Expense = require('../models/Expense');
const cloudinary = require('../utils/Cloudinary');
const fs = require('fs');
const { BadRequestError, NotFoundError } = require('../utils/Errors');
const { checkPermission } = require('../utils/checkPermission');
const { parsePagination, buildPaginatedResponse } = require('../utils/pagination');
const { toLeanExpense, sanitizeExpenseForClient } = require('../utils/expenseDto');
const { logAudit } = require('../utils/auditLog');
const { notifyExpenseAdded } = require('../utils/notifyExpense');
const User = require('../models/User');

// Helper: uploads multiple screenshots in parallel, returns arrays of URLs and public IDs
async function uploadUPIScreenshots(files) {
    const results = await Promise.all(
        files.map(async (file) => {
            try {
                const result = await cloudinary.uploader.upload(file.path, {
                    folder: 'expense-uploads/upi-screenshots',
                    resource_type: 'image',
                });
                return { url: result.secure_url, publicId: result.public_id };
            } finally {
                fs.promises.unlink(file.path).catch(() => {});
            }
        })
    );
    return {
        urls: results.map((r) => r.url),
        publicIds: results.map((r) => r.publicId),
    };
}

// Create new expense
const createExpense = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { name, category, amount, paymentMethod, paidAmount, solutionCard: solutionCardId } = req.body;

        if (!name || !category || !amount || !paymentMethod || paidAmount == null || !solutionCardId) {
            throw new BadRequestError('Missing required fields.');
        }
        if (+paidAmount > +amount) {
            throw new BadRequestError('Paid amount cannot be greater than total amount.');
        }

        // Permission check (owner/editor)
        const { role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['editor'], // viewer is excluded
            allowOwner: true
        });

        let upiScreenshotData = {};
        if (paymentMethod === 'upi') {
            if (!req.files || req.files.length === 0) {
                throw new BadRequestError('At least one UPI screenshot is required for UPI payments.');
            }
            upiScreenshotData = await uploadUPIScreenshots(req.files);
        }

        const paymentObj = {
            paidAmount: Number(paidAmount),
            paymentMethod,
            paidAt: new Date(),
            ...(paymentMethod === 'upi' ? {
                upiScreenshotUrls: upiScreenshotData.urls,
                upiScreenshotPublicIds: upiScreenshotData.publicIds,
            } : {}),
        };

        const newExpense = new Expense({
            name,
            category,
            amount,
            payments: [paymentObj],
            paidBy: userId,
            solutionCard: solutionCardId,
        });

        await newExpense.save();
        const populated = await Expense.findById(newExpense._id).populate('paidBy', 'name email');

        const actor = await User.findById(userId).select('name');
        await logAudit({
            entityType: 'expense',
            entityId: newExpense._id,
            action: 'create',
            actorId: userId,
            actorName: actor?.name || '',
            solutionCardId: solutionCardId,
            summary: `Expense created: ${name} ₹${amount}`,
        });

        notifyExpenseAdded({
            expense: newExpense,
            solutionCardId,
            addedByUserId: userId,
        }).catch((err) => console.error('Expense notification failed:', err.message));

        res.status(201).json({
            message: 'Expense created successfully.',
            expense: sanitizeExpenseForClient(populated),
            accessLevel,
        });
    } catch (error) {
        if (req.files && req.files.length) {
            req.files.forEach(f => fs.existsSync(f.path) && fs.unlinkSync(f.path));
        }
        next(error);
    }
};

// Add further payment to existing expense
const addPayment = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { expenseId } = req.params;
        const { paidAmount, paymentMethod } = req.body;

        if (!paidAmount || !paymentMethod) {
            throw new BadRequestError('paidAmount and paymentMethod are required.');
        }

        const { resource: expense, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: expenseId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true
        });

        if (+paidAmount > expense.amount - expense.advancePaid) {
            throw new BadRequestError('Paid amount exceeds pending amount.');
        }

        let upiScreenshotData = {};
        if (paymentMethod === 'upi') {
            if (!req.files || req.files.length === 0) {
                throw new BadRequestError('At least one UPI screenshot is required for UPI payments.');
            }
            upiScreenshotData = await uploadUPIScreenshots(req.files);
        }

        const paymentObj = {
            paidAmount: Number(paidAmount),
            paymentMethod,
            paidAt: new Date(),
            ...(paymentMethod === 'upi' ? {
                upiScreenshotUrls: upiScreenshotData.urls,
                upiScreenshotPublicIds: upiScreenshotData.publicIds,
            } : {}),
        };

        expense.payments.push(paymentObj);
        await expense.save();
        const populated = await Expense.findById(expense._id).populate('paidBy', 'name email');
        res.json({
            message: 'Payment added successfully.',
            expense: sanitizeExpenseForClient(populated),
            accessLevel,
        });
    } catch (error) {
        if (req.files && req.files.length) {
            req.files.forEach(f => fs.existsSync(f.path) && fs.unlinkSync(f.path));
        }
        next(error);
    }
};

// Retrieve expenses by solution card (paginated, lean by default)
const getExpensesBySolutionCard = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { solutionCardId } = req.params;
        const { category, paymentStatus, from, to, q, include } = req.query;
        const { page, limit, skip } = parsePagination(req.query);
        const includeFull = include === 'full';

        const { role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true
        });

        const filter = {
            solutionCard: solutionCardId,
            isDeleted: { $ne: true },
        };

        if (category) filter.category = category;
        if (paymentStatus) filter.paymentStatus = paymentStatus;
        if (from || to) {
            filter.createdAt = {};
            if (from) filter.createdAt.$gte = new Date(from);
            if (to) filter.createdAt.$lte = new Date(to);
        }
        if (q) {
            filter.$or = [
                { name: { $regex: q, $options: 'i' } },
                { category: { $regex: q, $options: 'i' } },
            ];
        }

        const [total, expenses] = await Promise.all([
            Expense.countDocuments(filter),
            Expense.find(filter)
                .populate('paidBy', 'name email')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit),
        ]);

        const mapped = includeFull
            ? expenses.map(sanitizeExpenseForClient)
            : expenses.map(toLeanExpense);

        res.json(
            buildPaginatedResponse({
                data: mapped,
                page,
                limit,
                total,
                extra: { expenses: mapped, accessLevel },
            })
        );
    } catch (error) {
        next(error);
    }
};

// Get single expense with full payment/screenshot details
const getExpenseById = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        const { resource: expense, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: id,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true,
        });

        const populated = await Expense.findById(expense._id).populate('paidBy', 'name email');
        res.json({ expense: sanitizeExpenseForClient(populated), accessLevel });
    } catch (error) {
        next(error);
    }
};

// Update expense
const updateExpense = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        const { resource: expense, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: id,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true
        });

        const { name, category, amount, payments, existingScreenshots } = req.body;

        let parsedPayments = [];
        if (payments) {
            try {
                parsedPayments = JSON.parse(payments);
            } catch {
                return res.status(400).json({ message: 'Invalid payments JSON format' });
            }
        }

        let parsedExistingScreenshots = [];
        if (existingScreenshots) {
            try {
                parsedExistingScreenshots = JSON.parse(existingScreenshots);
            } catch {
                return res.status(400).json({ message: 'Invalid existingScreenshots JSON format' });
            }
        }

        if (name !== undefined) expense.name = name;
        if (category !== undefined) expense.category = category;

        if (amount !== undefined) {
            const numericAmount = Number(amount);
            let newAdvancePaid = expense.advancePaid;
            if (parsedPayments.length > 0) {
                newAdvancePaid = parsedPayments.reduce(
                    (sum, p) => sum + Number(p.paidAmount || 0),
                    0
                );
            }
            if (newAdvancePaid > numericAmount) {
                throw new BadRequestError('Paid amount cannot be greater than total amount.');
            }

            expense.amount = numericAmount;
            expense.advancePaid = newAdvancePaid;
        } else {
            if (parsedPayments.length > 0) {
                const newAdvancePaid = parsedPayments.reduce(
                    (sum, p) => sum + Number(p.paidAmount || 0),
                    0
                );

                if (newAdvancePaid > expense.amount) {
                    throw new BadRequestError('Paid amount cannot be greater than total amount.');
                }

                expense.advancePaid = newAdvancePaid;
            }
        }


        if (parsedPayments.length > 0) {
            parsedPayments.forEach(payment => {
                if (payment.paymentMethod === 'upi') {
                    payment.upiScreenshotUrls = parsedExistingScreenshots;
                }
            });
            expense.payments = parsedPayments;
        } else if (parsedExistingScreenshots.length > 0 && expense.payments.length > 0) {
            expense.payments[0].upiScreenshotUrls = parsedExistingScreenshots;
        }

        if (req.files && req.files.length > 0) {
            const uploaded = await uploadUPIScreenshots(req.files);
            if (expense.payments.length > 0) {
                expense.payments[0].upiScreenshotUrls = [
                    ...(expense.payments[0].upiScreenshotUrls || []),
                    ...uploaded.urls,
                ];
                expense.payments[0].upiScreenshotPublicIds = [
                    ...(expense.payments[0].upiScreenshotPublicIds || []),
                    ...uploaded.publicIds,
                ];
            }
        }

        await expense.save();
        const populated = await Expense.findById(expense._id).populate('paidBy', 'name email');
        res.json({
            message: 'Expense updated successfully.',
            expense: sanitizeExpenseForClient(populated),
            accessLevel,
        });
    } catch (error) {
        if (req.files && req.files.length) {
            req.files.forEach(f => fs.existsSync(f.path) && fs.unlinkSync(f.path));
        }
        next(error);
    }
};

// Delete expense
const deleteExpense = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        const { resource: expense, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: id,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true
        });

        if (accessLevel !== 'owner' && accessLevel !== 'editor' && !expense.paidBy.equals(userId)) {
            throw new BadRequestError('You do not have permission to delete this expense.');
        }

        const publicIds = [];
        for (const payment of expense.payments) {
            if (Array.isArray(payment.upiScreenshotPublicIds)) {
                publicIds.push(...payment.upiScreenshotPublicIds.filter(Boolean));
            }
        }
        if (publicIds.length) {
            await Promise.all(
                publicIds.map((publicId) =>
                    cloudinary.uploader.destroy(publicId).catch((err) => {
                        console.error(`Cloudinary destroy failed for ${publicId}:`, err.message);
                    })
                )
            );
        }

        await expense.deleteOne();
        res.json({ message: 'Expense deleted successfully.', accessLevel });
    } catch (error) {
        next(error);
    }
};

// Restore expense
const restoreExpense = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        const { resource: expense, solutionCard, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: id,
            userId,
            allowedRoles: [],
            allowOwner: true
        });

        if (!solutionCard.owner.equals(userId)) {
            throw new BadRequestError('Only owner can restore this expense.');
        }

        if (!expense.isDeleted) {
            return res.status(400).json({ message: 'Expense is not deleted.' });
        }

        expense.isDeleted = false;
        await expense.save();
        res.json({ message: 'Expense restored successfully.', expense, accessLevel });
    } catch (error) {
        next(error);
    }
};

// Get deleted expenses by solution card
const getDeletedExpensesBySolutionCard = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { solutionCardId } = req.params;

        const { solutionCard, role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: [],
            allowOwner: true
        });

        if (!solutionCard.owner.equals(userId)) {
            throw new BadRequestError('Only owner can view deleted expenses.');
        }

        const { page, limit, skip } = parsePagination(req.query);
        const filter = { solutionCard: solutionCardId, isDeleted: true };
        const [total, deletedExpenses] = await Promise.all([
            Expense.countDocuments(filter),
            Expense.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit),
        ]);

        const mapped = deletedExpenses.map(toLeanExpense);
        res.json(
            buildPaginatedResponse({
                data: mapped,
                page,
                limit,
                total,
                extra: { deletedExpenses: mapped, accessLevel },
            })
        );
    } catch (error) {
        next(error);
    }
};

module.exports = {
    createExpense,
    addPayment,
    getExpensesBySolutionCard,
    getExpenseById,
    updateExpense,
    deleteExpense,
    restoreExpense,
    getDeletedExpensesBySolutionCard
};
