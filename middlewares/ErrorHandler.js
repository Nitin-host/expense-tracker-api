function errorHandler(err, req, res, next) {
    console.error(
        `[${new Date().toISOString()}] Error: ${err.statusCode || 500} ${err.message}\n${err.stack}`
    );

    const status = err.statusCode || 500;
    const code =
        err.statusCode
            ? status === 400
                ? 'BAD_REQUEST'
                : status === 401
                  ? 'UNAUTHORIZED'
                  : status === 403
                    ? 'FORBIDDEN'
                    : status === 404
                      ? 'NOT_FOUND'
                      : 'INTERNAL_ERROR'
            : 'INTERNAL_ERROR';

    const response = {
        success: false,
        error: {
            code,
            message: err.message || 'Internal Server Error',
        },
    };

    if (Array.isArray(err.errors)) {
        response.error.details = err.errors;
    }

    if (process.env.NODE_ENV === 'development') {
        response.error.stack = err.stack;
    }

    res.status(status).json(response);
}

module.exports = errorHandler;
