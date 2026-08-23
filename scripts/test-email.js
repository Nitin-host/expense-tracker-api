require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { sendEmail, getEmailDiagnostics } = require('../utils/Email');
const { buildUserWelcomeEmail } = require('../utils/userWelcomeEmail');

async function test() {
    const to = process.argv[2] || process.env.EMAIL_FROM || process.env.BREVO_SMTP_USER;
    const useWelcomeTemplate = process.argv.includes('--welcome');
    const diag = getEmailDiagnostics();

    console.log('Email diagnostics:', diag);
    console.log('Sending to:', to);
    console.log('Template:', useWelcomeTemplate ? 'user welcome (same as Create User)' : 'simple test');

    if (!to) {
        console.error('No recipient. Usage: node scripts/test-email.js [recipient@email.com] [--welcome]');
        process.exit(1);
    }

    try {
        if (useWelcomeTemplate) {
            const { html, text } = await buildUserWelcomeEmail({
                name: 'Test User',
                tempPassword: 'test-temp-password',
                email: to,
            });
            const messageId = await sendEmail(
                to,
                'Your Account Created - Expense Tracker (test)',
                html,
                text
            );
            console.log('SUCCESS: Welcome email sent. messageId:', messageId);
        } else {
            const messageId = await sendEmail(
                to,
                'Expense Tracker — email test',
                '<p>Brevo email is working.</p>',
                'Brevo email is working.'
            );
            console.log('SUCCESS: Email sent. messageId:', messageId);
        }
    } catch (err) {
        console.error('FAILED:', err.message);
        process.exit(1);
    }
}

test();
