const { loadTemplate, renderTemplate } = require('./emailTemplate');

/**
 * @param {{ name: string, tempPassword: string, email: string, purpose?: 'welcome' | 'reset' }} opts
 */
async function buildUserWelcomeEmail({ name, tempPassword, email, purpose = 'welcome' }) {
    const baseUrl = (process.env.FRONTEND_BASE_URL || '').replace(/\/$/, '');
    const resetLink = `${baseUrl}/change-password?email=${encodeURIComponent(email)}&temp=true`;
    const isReset = purpose === 'reset';
    const template = await loadTemplate('userCreationEmail.html');
    const html = renderTemplate(
        template,
        {
            name,
            tempPassword,
            resetLink,
            headline: isReset ? 'Password reset' : 'Welcome to the team',
            intro: isReset
                ? 'A new temporary password was requested for your Expense Tracker account.'
                : 'Your account has been created by the Expense Tracker team.',
            mustChange: isReset
                ? 'Use the temporary password below to sign in, then change your password. It expires in <b>2 days</b>.'
                : 'Use the temporary password below to sign in. You <b>must</b> change your password within <b>2 days</b> to keep your account active.',
        },
        ['resetLink', 'mustChange']
    );

    const text = [
        `Hi ${name},`,
        '',
        isReset
            ? 'A new temporary password was requested for your Expense Tracker account.'
            : 'Your Expense Tracker account has been created.',
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
