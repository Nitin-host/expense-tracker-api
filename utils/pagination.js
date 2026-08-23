/**
 * Parse page/limit query params with mobile-friendly defaults.
 */
function parsePagination(query, { defaultLimit = 20, maxLimit = 50 } = {}) {
    const page = Math.max(1, parseInt(query.page, 10) || 1);
    const limit = Math.min(maxLimit, Math.max(1, parseInt(query.limit, 10) || defaultLimit));
    const skip = (page - 1) * limit;
    return { page, limit, skip };
}

function buildPaginatedResponse({ data, page, limit, total, extra = {} }) {
    const totalPages = Math.max(1, Math.ceil(total / limit) || 1);
    return {
        data,
        page,
        limit,
        total,
        totalPages,
        hasMore: page * limit < total,
        ...extra,
    };
}

module.exports = { parsePagination, buildPaginatedResponse };
