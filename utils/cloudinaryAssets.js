const cloudinary = require('./Cloudinary');

const UPI_FOLDER = 'expense-uploads/upi-screenshots';

/**
 * Extract Cloudinary public_id from a secure/delivery URL.
 * e.g. .../upload/v123/expense-uploads/upi-screenshots/abc.jpg
 *   -> expense-uploads/upi-screenshots/abc
 */
function publicIdFromUrl(url) {
    if (!url || typeof url !== 'string') return null;
    try {
        const marker = '/upload/';
        const idx = url.indexOf(marker);
        if (idx === -1) return null;
        let path = url.slice(idx + marker.length);
        // Drop version segment (v1234567890/)
        path = path.replace(/^v\d+\//, '');
        // Drop transformation segments if present (e.g. w_100,c_fill/)
        if (path.includes('/') && !path.startsWith(UPI_FOLDER) && !path.startsWith('expense-uploads/')) {
            const parts = path.split('/');
            // Find expense-uploads start
            const folderIdx = parts.findIndex((p) => p === 'expense-uploads' || p.startsWith('expense-uploads'));
            if (folderIdx >= 0) path = parts.slice(folderIdx).join('/');
        }
        // Strip extension
        path = path.replace(/\.[a-zA-Z0-9]+$/, '');
        return path || null;
    } catch {
        return null;
    }
}

/** Collect unique public IDs from expense payment screenshot fields. */
function collectPublicIdsFromPayments(payments = []) {
    const ids = new Set();
    for (const payment of payments || []) {
        if (Array.isArray(payment.upiScreenshotPublicIds)) {
            payment.upiScreenshotPublicIds.filter(Boolean).forEach((id) => ids.add(id));
        }
        if (Array.isArray(payment.upiScreenshotUrls)) {
            payment.upiScreenshotUrls.forEach((url) => {
                const id = publicIdFromUrl(url);
                if (id) ids.add(id);
            });
        }
    }
    return [...ids];
}

async function destroyCloudinaryAssets(publicIds = []) {
    const unique = [...new Set((publicIds || []).filter(Boolean))];
    if (!unique.length) {
        return { deleted: [], failed: [] };
    }

    const results = await Promise.allSettled(
        unique.map((publicId) =>
            cloudinary.uploader.destroy(publicId, { resource_type: 'image', invalidate: true })
        )
    );

    const deleted = [];
    const failed = [];
    results.forEach((result, i) => {
        const publicId = unique[i];
        if (result.status === 'fulfilled') {
            const outcome = result.value?.result;
            if (outcome === 'ok' || outcome === 'not found') {
                deleted.push({ publicId, result: outcome });
            } else {
                failed.push({ publicId, error: outcome || 'unknown' });
            }
        } else {
            failed.push({ publicId, error: result.reason?.message || 'destroy failed' });
        }
    });

    return { deleted, failed };
}

async function listCloudinaryFolder(folder = UPI_FOLDER) {
    const resources = [];
    let nextCursor;

    do {
        const page = await cloudinary.api.resources({
            type: 'upload',
            resource_type: 'image',
            prefix: folder,
            max_results: 500,
            next_cursor: nextCursor,
        });
        resources.push(...(page.resources || []));
        nextCursor = page.next_cursor;
    } while (nextCursor);

    return resources;
}

module.exports = {
    UPI_FOLDER,
    publicIdFromUrl,
    collectPublicIdsFromPayments,
    destroyCloudinaryAssets,
    listCloudinaryFolder,
};
