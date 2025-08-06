const express = require('express');
const router = express.Router();
const userController = require('../controller/UserController');
const authenticateToken = require('../middlewares/AuthenticateToken');
const authorizeRole = require('../middlewares/AuthorizeRole');
const { validateCreateUser } = require('../middlewares/ValidateUser');
const asyncHandler = require('../middlewares/AsyncHandler'); // Async error wrapper

// Public route - user self registration with validation and async error handling
router.post('/create', validateCreateUser, asyncHandler(userController.createUser));

// Public login route with async error handling
router.post('/login', asyncHandler(userController.login));

router.get('/all/users',
    authenticateToken,
    authorizeRole(['super_admin', 'admin']),
    asyncHandler(userController.getAllUsers)
);

router.get(
    '/users/available-to-share',
    authenticateToken,
    asyncHandler(userController.getUsersForSharing)
);

// Public route to refresh access token (refresh token flow)
router.get('/refresh-token', asyncHandler(userController.refreshAccessToken));

// Change password route - consider protecting with authentication middleware if appropriate
// If you want to protect it, add authenticateToken middleware here
router.post('/change-password', asyncHandler(userController.changePassword));

// Protected route - only super_admin and admin can create users for others
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


// Public forgot/request temp password (no auth required)
router.post('/request-temp-password', asyncHandler(userController.requestTempPassword));

module.exports = router;
