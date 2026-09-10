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
const {
    collectPublicIdsFromPayments,
    destroyCloudinaryAssets,
    publicIdFromUrl,
} = require('../utils/cloudinaryAssets');
const User = require('../models/User');

const MONEY_EPS = 0.005;

function roundMoney(value) {
    return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
}

function normalizePaymentMethod(method) {
    return String(method || '').trim().toLowerCase();
}

function assertPaymentMethod(method) {
    const normalized = normalizePaymentMethod(method);
    if (!['cash', 'upi'].includes(normalized)) {
        throw new BadRequestError('paymentMethod must be cash or upi.');
    }
    return normalized;
}

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

        if (!name || !category || amount == null || amount === '' || paidAmount == null || paidAmount === '' || !solutionCardId) {
            throw new BadRequestError('Missing required fields.');
        }

        const billAmount = roundMoney(amount);
        const paid = roundMoney(paidAmount);
        if (!(billAmount > 0)) {
            throw new BadRequestError('Amount must be greater than 0.');
        }
        if (paid < 0) {
            throw new BadRequestError('Paid amount cannot be negative.');
        }
        if (paid - billAmount > MONEY_EPS) {
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

        const payments = [];
        if (paid > MONEY_EPS) {
            const method = assertPaymentMethod(paymentMethod);
            let upiScreenshotData = {};
            if (method === 'upi') {
                if (!req.files || req.files.length === 0) {
                    throw new BadRequestError('At least one UPI screenshot is required for UPI payments.');
                }
                upiScreenshotData = await uploadUPIScreenshots(req.files);
            }

            payments.push({
                paidAmount: paid,
                paymentMethod: method,
                paidAt: new Date(),
                ...(method === 'upi'
                    ? {
                          upiScreenshotUrls: upiScreenshotData.urls,
                          upiScreenshotPublicIds: upiScreenshotData.publicIds,
                      }
                    : { upiScreenshotUrls: [], upiScreenshotPublicIds: [] }),
            });
        }

        const newExpense = new Expense({
            name,
            category,
            amount: billAmount,
            payments,
            paidBy: userId,
            solutionCard: solutionCardId,
        });

        await newExpense.save();
        const populated = await Expense.findById(newExpense._id).populate('paidBy', 'name email');

        User.findById(userId).select('name').lean().then((actor) =>
            logAudit({
                entityType: 'expense',
                entityId: newExpense._id,
                action: 'create',
                actorId: userId,
                actorName: actor?.name || '',
                solutionCardId: solutionCardId,
                summary: `Expense created: ${name} ₹${billAmount}`,
            }).catch((err) => console.error('Audit log failed:', err.message))
        );

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

        if (paidAmount == null || paidAmount === '' || !paymentMethod) {
            throw new BadRequestError('paidAmount and paymentMethod are required.');
        }

        const method = assertPaymentMethod(paymentMethod);
        const paid = roundMoney(paidAmount);
        if (!(paid > 0)) {
            throw new BadRequestError('Paid amount must be greater than 0.');
        }

        const { resource: expense, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: expenseId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true
        });

        const pending = roundMoney(expense.amount - expense.advancePaid);
        if (paid - pending > MONEY_EPS) {
            throw new BadRequestError('Paid amount exceeds pending amount.');
        }

        let upiScreenshotData = {};
        if (method === 'upi') {
            if (!req.files || req.files.length === 0) {
                throw new BadRequestError('At least one UPI screenshot is required for UPI payments.');
            }
            upiScreenshotData = await uploadUPIScreenshots(req.files);
        }

        const paymentObj = {
            paidAmount: paid,
            paymentMethod: method,
            paidAt: new Date(),
            ...(method === 'upi'
                ? {
                      upiScreenshotUrls: upiScreenshotData.urls,
                      upiScreenshotPublicIds: upiScreenshotData.publicIds,
                  }
                : { upiScreenshotUrls: [], upiScreenshotPublicIds: [] }),
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

function parsePaymentIndex(raw) {
    const index = Number.parseInt(raw, 10);
    if (!Number.isInteger(index) || index < 0) {
        throw new BadRequestError('Invalid payment index.');
    }
    return index;
}

/**
 * Remove one installment from expense payment history.
 * Deletes the payment from MongoDB and destroys its UPI screenshots on Cloudinary.
 */
const removePayment = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { expenseId, paymentIndex } = req.params;
        const index = parsePaymentIndex(paymentIndex);

        const { resource: expense, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: expenseId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        if (!Array.isArray(expense.payments) || index >= expense.payments.length) {
            throw new BadRequestError('Payment installment not found.');
        }

        // Optional fingerprint guards against stale UI after concurrent edits
        const expectedAmount = req.body?.paidAmount ?? req.query?.paidAmount;
        const target = expense.payments[index];
        if (
            expectedAmount != null &&
            expectedAmount !== '' &&
            Math.abs(roundMoney(expectedAmount) - roundMoney(target.paidAmount)) > MONEY_EPS
        ) {
            throw new BadRequestError(
                'This payment was changed by someone else. Refresh history and try again.'
            );
        }

        // Snapshot plain payment data before splice (incl. screenshot URLs / publicIds)
        const removedPlain =
            typeof target.toObject === 'function' ? target.toObject() : { ...target };
        const removedPublicIds = collectPublicIdsFromPayments([removedPlain]);

        expense.payments.splice(index, 1);
        expense.markModified('payments');
        await expense.save();

        // DB is already updated — cleanup Cloudinary in background so mobile clients
        // are not blocked waiting on remote image deletes.
        if (removedPublicIds.length) {
            destroyCloudinaryAssets(removedPublicIds)
                .then(({ deleted, failed }) => {
                    failed.forEach((f) =>
                        console.error(`Cloudinary cleanup failed for ${f.publicId}:`, f.error)
                    );
                    console.log(
                        `Payment remove on expense ${expenseId}: Cloudinary deleted=${deleted.length}` +
                            (failed.length ? `, failed=${failed.length}` : '')
                    );
                })
                .catch((err) =>
                    console.error('Cloudinary cleanup error after payment remove:', err.message)
                );
        }

        User.findById(userId).select('name').lean().then((actor) =>
            logAudit({
                entityType: 'expense',
                entityId: expense._id,
                action: 'payment_remove',
                actorId: userId,
                actorName: actor?.name || '',
                solutionCardId: expense.solutionCard?._id || expense.solutionCard,
                summary: `Removed ${String(removedPlain.paymentMethod || '').toUpperCase()} payment ₹${roundMoney(removedPlain.paidAmount)} from ${expense.name}`,
            }).catch((err) => console.error('Audit log failed:', err.message))
        );

        const populated = await Expense.findById(expense._id).populate('paidBy', 'name email');
        res.json({
            message: 'Payment removed successfully.',
            expense: sanitizeExpenseForClient(populated),
            accessLevel,
            storage: {
                dbRemoved: true,
                cloudinaryCleanupQueued: removedPublicIds.length,
            },
        });
    } catch (error) {
        next(error);
    }
};

/**
 * Edit one installment (amount / method / screenshots) without wiping other history rows.
 */
const updatePayment = async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { expenseId, paymentIndex } = req.params;
        const index = parsePaymentIndex(paymentIndex);
        const { paidAmount, paymentMethod, existingScreenshots } = req.body;

        const { resource: expense, role: accessLevel } = await checkPermission({
            resourceType: 'expense',
            resourceId: expenseId,
            userId,
            allowedRoles: ['editor'],
            allowOwner: true,
        });

        if (!Array.isArray(expense.payments) || index >= expense.payments.length) {
            throw new BadRequestError('Payment installment not found.');
        }

        const payment = expense.payments[index];
        const oldPublicIds = collectPublicIdsFromPayments([payment]);

        const nextPaid =
            paidAmount != null && paidAmount !== ''
                ? roundMoney(paidAmount)
                : roundMoney(payment.paidAmount);
        if (!(nextPaid > 0)) {
            throw new BadRequestError('Paid amount must be greater than 0.');
        }

        const nextMethod =
            paymentMethod != null && paymentMethod !== ''
                ? assertPaymentMethod(paymentMethod)
                : assertPaymentMethod(payment.paymentMethod);

        const otherPaid = roundMoney(
            expense.payments.reduce((sum, p, i) => {
                if (i === index) return sum;
                return sum + Number(p.paidAmount || 0);
            }, 0)
        );
        if (otherPaid + nextPaid - roundMoney(expense.amount) > MONEY_EPS) {
            throw new BadRequestError(
                'Updated payment would make total paid greater than bill amount.'
            );
        }

        let keptUrls = [];
        if (existingScreenshots) {
            try {
                const parsed = JSON.parse(existingScreenshots);
                keptUrls = Array.isArray(parsed) ? parsed.filter(Boolean) : [];
            } catch {
                throw new BadRequestError('Invalid existingScreenshots JSON format.');
            }
        } else if (nextMethod === 'upi') {
            keptUrls = Array.isArray(payment.upiScreenshotUrls)
                ? payment.upiScreenshotUrls.filter(Boolean)
                : [];
        }

        let uploaded = { urls: [], publicIds: [] };
        if (req.files && req.files.length > 0) {
            if (nextMethod !== 'upi') {
                throw new BadRequestError('UPI screenshots can only be attached to UPI payments.');
            }
            uploaded = await uploadUPIScreenshots(req.files);
        }

        if (nextMethod === 'upi') {
            const urls = [...keptUrls, ...uploaded.urls];
            if (!urls.length) {
                throw new BadRequestError('At least one UPI screenshot is required for UPI payments.');
            }
            payment.paymentMethod = 'upi';
            payment.paidAmount = nextPaid;
            payment.upiScreenshotUrls = urls;
            payment.upiScreenshotPublicIds = urls
                .map((url) => publicIdFromUrl(url))
                .filter(Boolean);
            // Prefer uploaded publicIds when available
            if (uploaded.publicIds.length) {
                const fromKept = keptUrls.map((url) => publicIdFromUrl(url)).filter(Boolean);
                payment.upiScreenshotPublicIds = [...fromKept, ...uploaded.publicIds];
            }
        } else {
            payment.paymentMethod = 'cash';
            payment.paidAmount = nextPaid;
            payment.upiScreenshotUrls = [];
            payment.upiScreenshotPublicIds = [];
        }

        if (!payment.paidAt) payment.paidAt = new Date();

        expense.markModified('payments');
        await expense.save();

        const keptPublicIds = new Set(collectPublicIdsFromPayments([payment]));
        const removedPublicIds = oldPublicIds.filter((id) => !keptPublicIds.has(id));
        if (removedPublicIds.length) {
            destroyCloudinaryAssets(removedPublicIds)
                .then(({ failed }) => {
                    failed.forEach((f) =>
                        console.error(`Cloudinary cleanup failed for ${f.publicId}:`, f.error)
                    );
                })
                .catch((err) =>
                    console.error('Cloudinary cleanup error after payment update:', err.message)
                );
        }

        User.findById(userId).select('name').lean().then((actor) =>
            logAudit({
                entityType: 'expense',
                entityId: expense._id,
                action: 'payment_update',
                actorId: userId,
                actorName: actor?.name || '',
                solutionCardId: expense.solutionCard?._id || expense.solutionCard,
                summary: `Updated payment #${index + 1} on ${expense.name} to ₹${nextPaid} ${nextMethod.toUpperCase()}`,
            }).catch((err) => console.error('Audit log failed:', err.message))
        );

        const populated = await Expense.findById(expense._id).populate('paidBy', 'name email');
        res.json({
            message: 'Payment updated successfully.',
            expense: sanitizeExpenseForClient(populated),
            accessLevel,
            storage: { cloudinaryCleanupQueued: removedPublicIds.length },
        });
    } catch (error) {
        if (req.files && req.files.length) {
            req.files.forEach((f) => fs.existsSync(f.path) && fs.unlinkSync(f.path));
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
            if (from) {
                // YYYY-MM-DD from <input type="date"> → local start of day
                if (/^\d{4}-\d{2}-\d{2}$/.test(from)) {
                    const [y, m, d] = from.split('-').map(Number);
                    filter.createdAt.$gte = new Date(y, m - 1, d, 0, 0, 0, 0);
                } else {
                    filter.createdAt.$gte = new Date(from);
                }
            }
            if (to) {
                // Inclusive end-of-day so same-day expenses are not dropped
                if (/^\d{4}-\d{2}-\d{2}$/.test(to)) {
                    const [y, m, d] = to.split('-').map(Number);
                    filter.createdAt.$lte = new Date(y, m - 1, d, 23, 59, 59, 999);
                } else {
                    filter.createdAt.$lte = new Date(to);
                }
            }
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
                .limit(limit)
                .lean(),
        ]);

        // toLeanExpense strips screenshot URLs/publicIds from the client payload after counting them.
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

        let parsedPayments = null;
        if (payments !== undefined && payments !== null && payments !== '') {
            try {
                parsedPayments = JSON.parse(payments);
                if (!Array.isArray(parsedPayments)) {
                    throw new Error('not array');
                }
            } catch {
                return res.status(400).json({
                    error: { code: 'BAD_REQUEST', message: 'Invalid payments JSON format' },
                });
            }
        }

        let parsedExistingScreenshots = [];
        if (existingScreenshots) {
            try {
                parsedExistingScreenshots = JSON.parse(existingScreenshots);
            } catch {
                return res.status(400).json({
                    error: { code: 'BAD_REQUEST', message: 'Invalid existingScreenshots JSON format' },
                });
            }
        }

        if (name !== undefined) expense.name = name;
        if (category !== undefined) expense.category = category;

        if (amount !== undefined) {
            const numericAmount = roundMoney(amount);
            if (!(numericAmount > 0)) {
                throw new BadRequestError('Amount must be greater than 0.');
            }
            let newAdvancePaid = roundMoney(expense.advancePaid);
            if (Array.isArray(parsedPayments)) {
                newAdvancePaid = roundMoney(
                    parsedPayments.reduce((sum, p) => sum + Number(p.paidAmount || 0), 0)
                );
            }
            if (newAdvancePaid - numericAmount > MONEY_EPS) {
                throw new BadRequestError('Paid amount cannot be greater than total amount.');
            }

            expense.amount = numericAmount;
            expense.advancePaid = newAdvancePaid;
        } else if (Array.isArray(parsedPayments)) {
            const newAdvancePaid = roundMoney(
                parsedPayments.reduce((sum, p) => sum + Number(p.paidAmount || 0), 0)
            );

            if (newAdvancePaid - roundMoney(expense.amount) > MONEY_EPS) {
                throw new BadRequestError('Paid amount cannot be greater than total amount.');
            }

            expense.advancePaid = newAdvancePaid;
        }


        const oldPublicIds = collectPublicIdsFromPayments(expense.payments);

        if (Array.isArray(parsedPayments)) {
            if (parsedPayments.length === 0) {
                expense.payments = [];
            } else {
                const oldPayments = Array.isArray(expense.payments) ? expense.payments : [];
                const oldPaidSum = roundMoney(
                    oldPayments.reduce((sum, p) => sum + Number(p.paidAmount || 0), 0)
                );
                const newPaidSum = roundMoney(
                    parsedPayments.reduce((sum, p) => sum + Number(p.paidAmount || 0), 0)
                );

                // Editing name/category/bill should NOT wipe multi-payment history
                // (Add Payment creates separate cash/UPI rows with their own paidAt).
                const preservePaymentHistory =
                    parsedPayments.length === 1 &&
                    oldPayments.length > 1 &&
                    Math.abs(oldPaidSum - newPaidSum) < MONEY_EPS;

                if (preservePaymentHistory) {
                    // Keep installment rows as-is; only bill metadata was edited.
                    expense.payments = oldPayments;
                } else {
                    parsedPayments.forEach((payment, idx) => {
                        payment.paymentMethod = assertPaymentMethod(payment.paymentMethod);
                        payment.paidAmount = roundMoney(payment.paidAmount);
                        if (payment.paidAmount < 0) {
                            throw new BadRequestError('Paid amount cannot be negative.');
                        }

                        if (payment.paymentMethod === 'upi') {
                            const ownUrls = Array.isArray(payment.upiScreenshotUrls)
                                ? payment.upiScreenshotUrls.filter(Boolean)
                                : [];
                            // Prefer each payment's own screenshots (multi-payment history).
                            // Fall back to shared existingScreenshots only for single-payment edits.
                            payment.upiScreenshotUrls =
                                ownUrls.length > 0
                                    ? ownUrls
                                    : parsedPayments.length === 1
                                      ? parsedExistingScreenshots
                                      : ownUrls;
                            payment.upiScreenshotPublicIds = (payment.upiScreenshotUrls || [])
                                .map((url) => publicIdFromUrl(url))
                                .filter(Boolean);
                        } else {
                            payment.upiScreenshotUrls = [];
                            payment.upiScreenshotPublicIds = [];
                        }
                        if (!payment.paidAt) {
                            payment.paidAt =
                                oldPayments[idx]?.paidAt ||
                                oldPayments[0]?.paidAt ||
                                new Date();
                        }
                    });
                    expense.payments = parsedPayments;
                }
            }
        } else if (parsedExistingScreenshots.length > 0 && expense.payments.length > 0) {
            expense.payments[0].upiScreenshotUrls = parsedExistingScreenshots;
            expense.payments[0].upiScreenshotPublicIds = parsedExistingScreenshots
                .map((url) => publicIdFromUrl(url))
                .filter(Boolean);
        }

        if (req.files && req.files.length > 0) {
            const uploaded = await uploadUPIScreenshots(req.files);
            const target =
                expense.payments.find((p) => p.paymentMethod === 'upi') || expense.payments[0];
            if (!target || target.paymentMethod !== 'upi') {
                throw new BadRequestError('UPI screenshots can only be attached to UPI payments.');
            }
            target.upiScreenshotUrls = [
                ...(target.upiScreenshotUrls || []),
                ...uploaded.urls,
            ];
            target.upiScreenshotPublicIds = [
                ...(target.upiScreenshotPublicIds || []),
                ...uploaded.publicIds,
            ];
        }

        // Every UPI installment must keep at least one screenshot
        for (const payment of expense.payments) {
            if (
                payment.paymentMethod === 'upi' &&
                Number(payment.paidAmount) > MONEY_EPS &&
                !(payment.upiScreenshotUrls && payment.upiScreenshotUrls.length)
            ) {
                throw new BadRequestError('At least one UPI screenshot is required for UPI payments.');
            }
        }

        await expense.save();

        const keptPublicIds = new Set(collectPublicIdsFromPayments(expense.payments));
        const removedPublicIds = oldPublicIds.filter((id) => !keptPublicIds.has(id));
        if (removedPublicIds.length) {
            destroyCloudinaryAssets(removedPublicIds).then(({ failed }) => {
                failed.forEach((f) =>
                    console.error(`Cloudinary cleanup failed for ${f.publicId}:`, f.error)
                );
            });
        }

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

        const publicIds = collectPublicIdsFromPayments(expense.payments);

        // Remove DB record first so UI is not blocked; then clean Cloudinary.
        await expense.deleteOne();

        if (publicIds.length) {
            const { deleted, failed } = await destroyCloudinaryAssets(publicIds);
            if (failed.length) {
                failed.forEach((f) =>
                    console.error(`Cloudinary destroy failed for ${f.publicId}:`, f.error)
                );
            }
            console.log(
                `Expense ${id}: removed ${deleted.length} Cloudinary asset(s)` +
                    (failed.length ? `, ${failed.length} failed` : '')
            );
        }

        res.json({
            message: 'Expense deleted successfully.',
            accessLevel,
            cloudinaryDeleted: publicIds.length,
        });
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
    removePayment,
    updatePayment,
    getExpensesBySolutionCard,
    getExpenseById,
    updateExpense,
    deleteExpense,
    restoreExpense,
    getDeletedExpensesBySolutionCard
};
