/**
 * Compare Cloudinary UPI screenshots with MongoDB references.
 * Keeps files that exist in the DB; deletes orphan Cloudinary assets.
 *
 * Usage:
 *   node scripts/cleanup-cloudinary-orphans.js          # dry-run (default)
 *   node scripts/cleanup-cloudinary-orphans.js --delete # actually delete orphans
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const mongoose = require('mongoose');
const Expense = require('../models/Expense');
const {
    UPI_FOLDER,
    collectPublicIdsFromPayments,
    listCloudinaryFolder,
    destroyCloudinaryAssets,
} = require('../utils/cloudinaryAssets');

async function collectDbPublicIds() {
    const expenses = await Expense.find({})
        .select('payments.upiScreenshotPublicIds payments.upiScreenshotUrls')
        .lean();

    const ids = new Set();
    let expensesWithScreenshots = 0;

    for (const expense of expenses) {
        const fromExpense = collectPublicIdsFromPayments(expense.payments);
        if (fromExpense.length) expensesWithScreenshots += 1;
        fromExpense.forEach((id) => ids.add(id));
    }

    return { ids, expenseCount: expenses.length, expensesWithScreenshots };
}

async function main() {
    const shouldDelete = process.argv.includes('--delete');
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
        console.error('MONGO_URI missing in .env');
        process.exit(1);
    }
    if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY) {
        console.error('Cloudinary credentials missing in .env');
        process.exit(1);
    }

    console.log(`Mode: ${shouldDelete ? 'DELETE orphans' : 'DRY-RUN (no deletes)'}`);
    console.log(`Folder: ${UPI_FOLDER}`);
    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri);

    const { ids: dbIds, expenseCount, expensesWithScreenshots } = await collectDbPublicIds();
    console.log(`DB expenses: ${expenseCount}`);
    console.log(`Expenses with screenshots: ${expensesWithScreenshots}`);
    console.log(`Unique public IDs in DB: ${dbIds.size}`);

    console.log('Listing Cloudinary resources...');
    const cloudResources = await listCloudinaryFolder(UPI_FOLDER);
    console.log(`Cloudinary files in folder: ${cloudResources.length}`);

    const orphanIds = [];
    const keptIds = [];
    for (const resource of cloudResources) {
        const publicId = resource.public_id;
        if (dbIds.has(publicId)) keptIds.push(publicId);
        else orphanIds.push(publicId);
    }

    // DB refs that are missing from Cloudinary (informational)
    const cloudIdSet = new Set(cloudResources.map((r) => r.public_id));
    const missingInCloud = [...dbIds].filter((id) => !cloudIdSet.has(id));

    console.log('\n--- Summary ---');
    console.log(`Keep (in DB + Cloudinary): ${keptIds.length}`);
    console.log(`Orphans (Cloudinary only): ${orphanIds.length}`);
    console.log(`Missing in Cloudinary (DB only): ${missingInCloud.length}`);

    if (orphanIds.length) {
        console.log('\nOrphan public IDs:');
        orphanIds.forEach((id) => console.log(`  - ${id}`));
    }
    if (missingInCloud.length) {
        console.log('\nDB references missing from Cloudinary:');
        missingInCloud.forEach((id) => console.log(`  - ${id}`));
    }

    if (!orphanIds.length) {
        console.log('\nNothing to delete. Cloudinary matches DB.');
        await mongoose.disconnect();
        return;
    }

    if (!shouldDelete) {
        console.log('\nDry-run only. Re-run with --delete to remove orphans.');
        await mongoose.disconnect();
        return;
    }

    console.log(`\nDeleting ${orphanIds.length} orphan asset(s)...`);
    const { deleted, failed } = await destroyCloudinaryAssets(orphanIds);
    console.log(`Deleted: ${deleted.length}`);
    if (failed.length) {
        console.log('Failed:');
        failed.forEach((f) => console.log(`  - ${f.publicId}: ${f.error}`));
    }

    await mongoose.disconnect();
    console.log('Done.');
}

main().catch(async (err) => {
    console.error(err);
    try {
        await mongoose.disconnect();
    } catch {
        /* ignore */
    }
    process.exit(1);
});
