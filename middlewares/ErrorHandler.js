// middlewares/errorHandler.js

function errorHandler(err, req, res, next) {
    // Log the error details server-side
    console.error(
        `[${new Date().toISOString()}] Error: ${err.statusCode || 500} ${err.message}\n${err.stack}`
    );

    // Set the HTTP status code (defaults to 500)
    const status = err.statusCode || 500;

    // Custom structure for the JSON response
    const response = {
        success: false,
        error: {
            message: err.message || 'Internal Server Error',
        },
    };

    // Optionally add stack only in dev environment
    if (process.env.NODE_ENV === 'development') {
        response.error.stack = err.stack;
    }

    res.status(status).json(response);
}

module.exports = errorHandler;
