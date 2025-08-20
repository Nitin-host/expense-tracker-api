// controllers/expenseController.js
const Expense = require('../models/Expense');
const cloudinary = require('../utils/Cloudinary');
const fs = require('fs');
const { BadRequestError, NotFoundError } = require('../utils/Errors');
const { checkPermission } = require('../utils/checkPermission');

// Helper: uploads multiple screenshots, returns arrays of URLs and public IDs
async function uploadUPIScreenshots(files) {
    const urls = [];
    const publicIds = [];
    for (const file of files) {
        const result = await cloudinary.uploader.upload(file.path, {
            folder: 'expense-uploads/upi-screenshots',
            resource_type: 'image',
        });
        urls.push(result.secure_url);
        publicIds.push(result.public_id);
        fs.unlinkSync(file.path);
    }
    return { urls, publicIds };
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
        res.status(201).json({ message: 'Expense created successfully.', expense: newExpense, accessLevel });
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
        res.json({ message: 'Payment added successfully.', expense, accessLevel });
    } catch (error) {
        if (req.files && req.files.length) {
            req.files.forEach(f => fs.existsSync(f.path) && fs.unlinkSync(f.path));
        }
        next(error);
    }
};

// Retrieve expenses by solution card
const getExpensesBySolutionCard = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { solutionCardId } = req.params;

        const { role: accessLevel } = await checkPermission({
            resourceType: 'solution',
            resourceId: solutionCardId,
            userId,
            allowedRoles: ['viewer', 'editor'],
            allowOwner: true
        });

        const expenses = await Expense.find({ solutionCard: solutionCardId })
            .populate('paidBy', 'name email')
            .sort({ createdAt: -1 });

        res.json({ expenses, accessLevel });
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
            const newScreenshotUrls = req.files.map(file => `/uploads/${file.filename}`);
            if (expense.payments.length > 0) {
                expense.payments[0].upiScreenshotUrls = [
                    ...(expense.payments[0].upiScreenshotUrls || []),
                    ...newScreenshotUrls,
                ];
            }
        }

        await expense.save();
        res.json({ message: 'Expense updated successfully.', expense, accessLevel });
    } catch (error) {
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

        for (const payment of expense.payments) {
            if (payment.upiScreenshotPublicIds && Array.isArray(payment.upiScreenshotPublicIds)) {
                for (const publicId of payment.upiScreenshotPublicIds) {
                    await cloudinary.uploader.destroy(publicId);
                }
            }
        }

        expense.isDeleted = true;
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

        const deletedExpenses = await Expense.find({
            solutionCard: solutionCardId,
            isDeleted: true
        }).sort({ createdAt: -1 });

        res.json({ deletedExpenses, accessLevel });
    } catch (error) {
        next(error);
    }
};

module.exports = {
    createExpense,
    addPayment,
    getExpensesBySolutionCard,
    updateExpense,
    deleteExpense,
    restoreExpense,
    getDeletedExpensesBySolutionCard
};
