const Expense = require('../models/Expense');
const SolutionCard = require('../models/SolutionCard');
const cloudinary = require('../utils/Cloudinary');
const fs = require('fs');
const { BadRequestError, NotFoundError, ForbiddenError } = require('../utils/Errors');

const getExpenseById = async (id) => {
    return await Expense.findById(id);
};

// Helper to get user role on solution card
const getUserRoleOnCard = (solutionCard, userId) => {
    if (solutionCard.owner.equals(userId)) return 'owner';
    const sharedUser = solutionCard.sharedWith.find(s => s.user.equals(userId));
    if (!sharedUser) return null;
    return sharedUser.role;
};

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

// Create new expense with initial payment (supports multiple screenshots)
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
        const solutionCard = await SolutionCard.findById(solutionCardId);
        if (!solutionCard) throw new NotFoundError('Solution card not found.');

        const role = getUserRoleOnCard(solutionCard, userId);
        if (!role || (role !== 'owner' && role !== 'editor')) {
            throw new ForbiddenError('You do not have permission to add expenses to this solution card.');
        }

        // UPI screenshots (multiple)
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
        res.status(201).json({ message: 'Expense created successfully.', expense: newExpense });
    } catch (error) {
        // Cleanup local temp files
        if (req.files && req.files.length) {
            req.files.forEach(f => fs.existsSync(f.path) && fs.unlinkSync(f.path));
        }
        next(error);
    }
};

// Add further payment to existing expense (supports multiple screenshots)
const addPayment = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { expenseId } = req.params;
        const { paidAmount, paymentMethod } = req.body;

        if (!paidAmount || !paymentMethod) {
            throw new BadRequestError('paidAmount and paymentMethod are required.');
        }
        const expense = await Expense.findById(expenseId);
        if (!expense) throw new NotFoundError('Expense not found.');

        const solutionCard = await SolutionCard.findById(expense.solutionCard);
        if (!solutionCard) throw new NotFoundError('Linked solution card not found.');

        const role = getUserRoleOnCard(solutionCard, userId);
        if (!role || (role !== 'owner' && role !== 'editor')) {
            throw new ForbiddenError('You do not have permission to add payments to this expense.');
        }

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
        res.json({ message: 'Payment added successfully.', expense });
    } catch (error) {
        if (req.files && req.files.length) {
            req.files.forEach(f => fs.existsSync(f.path) && fs.unlinkSync(f.path));
        }
        next(error);
    }
};

// Retrieve all expenses by solution card (with permission check)
const getExpensesBySolutionCard = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { solutionCardId } = req.params;
        const solutionCard = await SolutionCard.findById(solutionCardId);
        if (!solutionCard) throw new NotFoundError('Solution card not found.');

        const role = getUserRoleOnCard(solutionCard, userId);
        if (!role) throw new ForbiddenError('Access denied to this solution card.');

        const expenses = await Expense.find({ solutionCard: solutionCardId })
            .populate('paidBy', 'name email')
            .sort({ createdAt: -1 });

        res.json({ expenses });
    } catch (error) {
        next(error);
    }
};

// Update expense fields (not payments) - only owner/editor
const updateExpense = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        // Extract fields from req.body (all as strings, multipart form)
        const { name, category, amount, payments, existingScreenshots } = req.body;

        // Parse complex JSON fields safely
        let parsedPayments = [];
        if (payments) {
            try {
                parsedPayments = JSON.parse(payments);
            } catch (e) {
                // If parsing fails, ignore or handle error
                return res.status(400).json({ message: 'Invalid payments JSON format' });
            }
        }

        let parsedExistingScreenshots = [];
        if (existingScreenshots) {
            try {
                parsedExistingScreenshots = JSON.parse(existingScreenshots);
            } catch (e) {
                return res.status(400).json({ message: 'Invalid existingScreenshots JSON format' });
            }
        }

        const expense = await Expense.findById(id);
        if (!expense) throw new NotFoundError('Expense not found.');

        const solutionCard = await SolutionCard.findById(expense.solutionCard);
        if (!solutionCard) throw new NotFoundError('Linked solution card not found.');

        const role = getUserRoleOnCard(solutionCard, userId);
        if (!role || (role !== 'owner' && role !== 'editor')) {
            throw new ForbiddenError('You do not have permission to update this expense.');
        }

        // Update basic fields
        if (name !== undefined) expense.name = name;
        if (category !== undefined) expense.category = category;

        if (amount !== undefined) {
            const numericAmount = Number(amount);
            if (numericAmount < expense.advancePaid) {
                throw new BadRequestError('New amount cannot be less than total paid.');
            }
            expense.amount = numericAmount;
        }

        // Update payments if data provided
        if (parsedPayments.length > 0) {
            // For each payment, integrate existingScreenshots if applicable
            // Assuming the first payment corresponds to screenshots passed
            parsedPayments.forEach(payment => {
                if (payment.paymentMethod === 'upi') {
                    payment.upiScreenshotUrls = parsedExistingScreenshots;
                }
            });
            expense.payments = parsedPayments;
        } else if (parsedExistingScreenshots.length > 0 && expense.payments.length > 0) {
            // If no new payments but existing screenshots updated, update screenshots in first payment
            expense.payments[0].upiScreenshotUrls = parsedExistingScreenshots;
        }

        // Process new uploaded files
        if (req.files && req.files.length > 0) {
            // You should save/move files properly and generate URLs
            // Example: temporary URLs from uploaded files
            const newScreenshotUrls = req.files.map(file => `/uploads/${file.filename}`);

            if (expense.payments.length > 0) {
                // Append new screenshots to first payment (adjust if needed)
                expense.payments[0].upiScreenshotUrls = [
                    ...(expense.payments[0].upiScreenshotUrls || []),
                    ...newScreenshotUrls,
                ];
            }
        }

        await expense.save();
        res.json({ message: 'Expense updated successfully.', expense });
    } catch (error) {
        next(error);
    }
};

// Delete expense and all UPI screenshots (Cloudinary)
const deleteExpense = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        const expense = await Expense.findById(id);
        if (!expense) throw new NotFoundError('Expense not found.');

        const solutionCard = await SolutionCard.findById(expense.solutionCard);
        if (!solutionCard) throw new NotFoundError('Linked solution card not found.');

        const role = getUserRoleOnCard(solutionCard, userId);
        if (!role && !expense.paidBy.equals(userId)) {
            throw new ForbiddenError('You do not have permission to delete this expense.');
        }
        if (role !== 'owner' && role !== 'editor' && !expense.paidBy.equals(userId)) {
            throw new ForbiddenError('You do not have permission to delete this expense.');
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
        res.json({ message: 'Expense deleted successfully.' });
    } catch (error) {
        next(error);
    }
};

const restoreExpense = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        const expense = await Expense.findById(id);
        if (!expense) {
            throw new NotFoundError('Expense not found.');
        }

        const solutionCard = await SolutionCard.findById(expense.solutionCard);
        if (!solutionCard) {
            throw new NotFoundError('Linked solution card not found.');
        }

        // Only the owner can restore soft-deleted expense
        if (!solutionCard.owner.equals(userId)) {
            throw new ForbiddenError('Only owner can restore this expense.');
        }

        if (!expense.isDeleted) {
            return res.status(400).json({ message: 'Expense is not deleted.' });
        }

        expense.isDeleted = false;
        await expense.save();

        res.json({ message: 'Expense restored successfully.', expense });
    } catch (error) {
        next(error);
    }
};

const getDeletedExpensesBySolutionCard = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { solutionCardId } = req.params;

        const solutionCard = await SolutionCard.findById(solutionCardId);
        if (!solutionCard) {
            throw new NotFoundError('Solution card not found.');
        }

        // Only owner can view deleted expenses
        if (!solutionCard.owner.equals(userId)) {
            throw new ForbiddenError('Only owner can view deleted expenses.');
        }

        // Find expenses that are soft deleted for this solution card
        const deletedExpenses = await Expense.find({
            solutionCard: solutionCardId,
            isDeleted: true
        }).sort({ createdAt: -1 });

        res.json({ deletedExpenses });
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
    getDeletedExpensesBySolutionCard,
    getExpenseById
};
