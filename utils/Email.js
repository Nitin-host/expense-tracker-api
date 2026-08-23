const nodemailer = require('nodemailer');
require('dotenv').config();
const { BadRequestError } = require('./Errors');

const SMTP_HOST = process.env.BREVO_SMTP_HOST || 'smtp-relay.brevo.com';
const SMTP_PORT = Number(process.env.BREVO_SMTP_PORT) || 587;
const SMTP_USER = process.env.BREVO_SMTP_USER || process.env.EMAIL_USER;
const SMTP_KEY = process.env.BREVO_SMTP_KEY?.trim();
const SENDER_EMAIL = process.env.EMAIL_FROM || process.env.BREVO_SENDER_EMAIL || SMTP_USER;
const SENDER_NAME = process.env.EMAIL_FROM_NAME || 'Expense Tracker';

function getApiKey() {
    return process.env.BREVO_API_KEY?.trim() || null;
}

function isFreeEmailDomain(email) {
    const domain = String(email || '').split('@')[1]?.toLowerCase();
    return ['gmail.com', 'googlemail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com'].includes(domain);
}

function getEmailDiagnostics() {
    const apiKey = getApiKey();
    const smtpReady = Boolean(SMTP_USER && SMTP_KEY);
    return {
        transport: apiKey ? 'brevo-api' : 'brevo-smtp',
        smtpFallbackAvailable: Boolean(apiKey && smtpReady),
        sender: SENDER_EMAIL,
        senderName: SENDER_NAME,
        freeSenderWarning: isFreeEmailDomain(SENDER_EMAIL),
        brevoApiKeySet: Boolean(apiKey),
        brevoSmtpConfigured: smtpReady,
    };
}

function normalizeRecipients(to) {
    const list = Array.isArray(to) ? to : [to];
    return list.map((e) => String(e || '').trim().toLowerCase()).filter(Boolean);
}

let transporter = null;

function getTransporter() {
    if (transporter) return transporter;

    if (!SMTP_USER || !SMTP_KEY) {
        throw new BadRequestError(
            'Brevo SMTP is not configured. Set BREVO_SMTP_USER and BREVO_SMTP_KEY, or use BREVO_API_KEY.'
        );
    }

    transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465,
        requireTLS: SMTP_PORT === 587,
        auth: { user: SMTP_USER, pass: SMTP_KEY },
    });

    return transporter;
}

async function sendViaBrevoApi(to, subject, html, textContent) {
    const apiKey = getApiKey();
    if (!apiKey) {
        throw new BadRequestError('BREVO_API_KEY is not set');
    }

    const recipients = normalizeRecipients(to).map((email) => ({ email }));
    if (!recipients.length) {
        throw new BadRequestError('No valid recipient email provided');
    }

    const payload = {
        sender: { name: SENDER_NAME, email: SENDER_EMAIL },
        to: recipients,
        subject,
        htmlContent: html,
    };
    if (textContent) payload.textContent = textContent;

    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
            accept: 'application/json',
            'content-type': 'application/json',
            'api-key': apiKey,
        },
        body: JSON.stringify(payload),
    });

    const body = await response.json().catch(() => ({}));

    if (!response.ok) {
        const detail = body?.message || body?.code || response.statusText;
        if (response.status === 401 && /IP address/i.test(detail)) {
            const ipError = new BadRequestError(
                'Brevo blocked this server IP. Add your IP in Brevo → Security → Authorized IPs: https://app.brevo.com/security/authorised_ips'
            );
            ipError.code = 'BREVO_IP_BLOCKED';
            throw ipError;
        }
        throw new BadRequestError(`Brevo API error (${response.status}): ${detail}`);
    }

    if (!body.messageId) {
        throw new BadRequestError('Brevo did not confirm email delivery (missing messageId).');
    }

    console.log(`[Email] Sent to ${recipients.map((r) => r.email).join(', ')} — messageId: ${body.messageId}`);
    return body.messageId;
}

async function sendViaSmtp(to, subject, html, textContent) {
    const transport = getTransporter();
    const recipients = normalizeRecipients(to).join(', ');

    try {
        const info = await transport.sendMail({
            from: `"${SENDER_NAME}" <${SENDER_EMAIL}>`,
            to: recipients,
            subject,
            html,
            text: textContent,
        });
        console.log(`[Email] SMTP sent to ${recipients} — messageId: ${info.messageId}`);
        return info.messageId;
    } catch (err) {
        throw new BadRequestError(
            err.message?.includes('Authentication failed') || err.responseCode === 535
                ? 'Brevo SMTP login failed. Set BREVO_API_KEY in .env instead.'
                : `Email send failed: ${err.message}`
        );
    }
}

/**
 * @param {string|string[]} to
 * @param {string} subject
 * @param {string} html
 * @param {string} [textContent] plain-text fallback for deliverability
 * @returns {Promise<string>} messageId
 */
const sendEmail = async (to, subject, html, textContent = '') => {
    const apiKey = getApiKey();
    if (apiKey) {
        try {
            return await sendViaBrevoApi(to, subject, html, textContent);
        } catch (err) {
            const ipBlocked =
                err.code === 'BREVO_IP_BLOCKED' ||
                /blocked this server IP|IP address/i.test(err.message || '');
            const canUseSmtp = SMTP_USER && SMTP_KEY;

            if (ipBlocked && canUseSmtp) {
                console.warn('[Email] Brevo API blocked server IP — falling back to SMTP relay');
                return sendViaSmtp(to, subject, html, textContent);
            }
            throw err;
        }
    }
    return sendViaSmtp(to, subject, html, textContent);
};

const forgotEmail = sendEmail;

module.exports = { sendEmail, forgotEmail, getEmailDiagnostics };
