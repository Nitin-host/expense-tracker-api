const { loadTemplate, renderTemplate } = require('./emailTemplate');

async function buildUserWelcomeEmail({ name, tempPassword, email }) {
    const baseUrl = (process.env.FRONTEND_BASE_URL || '').replace(/\/$/, '');
    const resetLink = `${baseUrl}/change-password?email=${encodeURIComponent(email)}&temp=true`;
    const template = await loadTemplate('userCreationEmail.html');
    const html = renderTemplate(template, { name, tempPassword, resetLink }, ['resetLink']);

    const text = [
        `Hi ${name},`,
        '',
        'Your Expense Tracker account has been created.',
        `Temporary password: ${tempPassword}`,
        `Change your password here: ${resetLink}`,
        '',
        'This password expires in 2 days.',
    ].join('\n');

    return { html, text, resetLink };
}

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

module.exports = { buildUserWelcomeEmail, normalizeEmail };
