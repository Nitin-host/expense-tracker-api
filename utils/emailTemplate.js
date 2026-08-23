const fs = require('fs/promises');
const path = require('path');

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const templateCache = new Map();

async function loadTemplate(filename) {
    if (templateCache.has(filename)) {
        return templateCache.get(filename);
    }
    const content = await fs.readFile(path.join(__dirname, '..', 'templates', filename), 'utf-8');
    templateCache.set(filename, content);
    return content;
}

function renderTemplate(template, vars, rawKeys = []) {
    let html = template;
    for (const [key, value] of Object.entries(vars)) {
        const safe = rawKeys.includes(key) ? String(value ?? '') : escapeHtml(value);
        html = html.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), safe);
    }
    return html;
}

async function buildPasswordResetOtpEmail({ name, otp, expiryMinutes = 10 }) {
    const template = await loadTemplate('forgetPasswordEmail.html');
    const html = renderTemplate(template, { name, otp, expiryMinutes });
    const text = [
        `Hi ${name},`,
        '',
        'We received a request to reset your password.',
        `Your OTP is: ${otp}`,
        `It expires in ${expiryMinutes} minutes.`,
        '',
        'If you did not request this, ignore this email.',
    ].join('\n');
    return { html, text };
}

async function buildSolutionSharedEmail({
    name,
    ownerName,
    role,
    solutionName,
    solutionId,
}) {
    const baseUrl = (process.env.FRONTEND_BASE_URL || '').replace(/\/$/, '');
    const solutionLink = `${baseUrl}/solution/${solutionId}/dashboard`;
    const template = await loadTemplate('solutionShared.html');
    const html = renderTemplate(
        template,
        {
            name,
            ownerName,
            role,
            solutionName: solutionName || 'Untitled Solution',
            solutionLink,
            year: new Date().getFullYear(),
        },
        ['solutionLink']
    );
    const text = [
        `Hi ${name},`,
        '',
        `${ownerName} shared "${solutionName || 'Untitled Solution'}" with you as ${role}.`,
        `Open it here: ${solutionLink}`,
        '',
        'If you were not expecting this, you can ignore this email.',
    ].join('\n');
    return { html, text, solutionLink };
}

async function buildExpenseAddedEmail({
    addedBy,
    solutionName,
    expenseName,
    category,
    amount,
    solutionId,
}) {
    const baseUrl = (process.env.FRONTEND_BASE_URL || '').replace(/\/$/, '');
    const expenseLink = solutionId ? `${baseUrl}/solution/${solutionId}/expense-data` : baseUrl;
    const amountFormatted = Number(amount).toFixed(2);
    const template = await loadTemplate('expenseAddedEmail.html');
    const html = renderTemplate(
        template,
        {
            addedBy: addedBy || 'Someone',
            solutionName: solutionName || 'Solution',
            expenseName,
            category,
            amount: amountFormatted,
            expenseLink,
        },
        ['expenseLink']
    );
    const text = [
        `${addedBy || 'Someone'} added an expense to ${solutionName || 'Solution'}.`,
        '',
        `Name: ${expenseName}`,
        `Category: ${category}`,
        `Amount: ₹${amountFormatted}`,
        expenseLink ? `View expenses: ${expenseLink}` : '',
    ]
        .filter(Boolean)
        .join('\n');
    return { html, text };
}

module.exports = {
    escapeHtml,
    loadTemplate,
    renderTemplate,
    buildPasswordResetOtpEmail,
    buildSolutionSharedEmail,
    buildExpenseAddedEmail,
};
