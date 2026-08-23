const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const userController = require('../controller/UserController');
const authenticateToken = require('../middlewares/AuthenticateToken');
const authorizeRole = require('../middlewares/AuthorizeRole');
const { validateCreateUser } = require('../middlewares/ValidateUser');
const asyncHandler = require('../middlewares/AsyncHandler');

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: {
            code: 'RATE_LIMIT',
            message: 'Too many auth attempts. Please try again after 15 minutes.',
        },
    },
});

const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: {
            code: 'RATE_LIMIT',
            message: 'Too many password-reset requests. Please try again later.',
        },
    },
});

router.post('/create', authLimiter, validateCreateUser, asyncHandler(userController.createUser));
router.post('/login', authLimiter, asyncHandler(userController.login));
router.post('/refresh', authLimiter, asyncHandler(userController.refreshAccessToken));
router.post('/logout', asyncHandler(userController.logout));

router.get(
    '/all/users',
    authenticateToken,
    authorizeRole(['super_admin', 'admin']),
    asyncHandler(userController.getAllUsers)
);

router.get(
    '/users/available-to-share',
    authenticateToken,
    asyncHandler(userController.getUsersForSharing)
);

router.post('/change-password', asyncHandler(userController.changePassword));

router.post('/forgot-password/send-otp', otpLimiter, asyncHandler(userController.sendPasswordResetOTP));
router.post('/forgot-password/verify-otp', otpLimiter, asyncHandler(userController.verifyPasswordResetOTP));
router.post('/forgot-password/reset', otpLimiter, asyncHandler(userController.resetPassword));

router.post(
    '/create-by-super-admin',
    authenticateToken,
    authorizeRole(['super_admin', 'admin']),
    asyncHandler(userController.createUserBySuperAdmin)
);

router.get(
    '/my-created-users',
    authenticateToken,
    authorizeRole(['super_admin', 'admin']),
    asyncHandler(userController.getCreatedUsers)
);

router.put(
    '/change-user-role',
    authenticateToken,
    authorizeRole(['super_admin']),
    asyncHandler(userController.changeUserRole)
);

router.delete(
    '/user/:userId',
    authenticateToken,
    authorizeRole(['admin', 'super_admin']),
    asyncHandler(userController.deleteUserBySuperAdmin)
);

router.post('/request-temp-password', otpLimiter, asyncHandler(userController.requestTempPassword));

module.exports = router;
