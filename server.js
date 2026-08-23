require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const errorHandler = require('./middlewares/ErrorHandler');
const { getEmailDiagnostics } = require('./utils/Email');
const collectedCashRoutes = require('./routers/collectedCashRoutes');
const userRouter = require('./routers/UserRouters');
const solutionCardRouter = require('./routers/SolutionCardRouters');
const expenseRouter = require('./routers/ExpenseRouter');
const dashboardRouter = require('./routers/DashboardRoutes');
const reportRouter = require('./routers/ReportRoutes');
const cookieParser = require('cookie-parser');

const app = express();

// Render/Heroku/Netlify proxies set X-Forwarded-For; required for express-rate-limit
if (process.env.TRUST_PROXY !== 'false') {
    const hops = process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : 1;
    app.set('trust proxy', Number.isFinite(hops) && hops > 0 ? hops : 1);
}

app.use(cookieParser());
app.use(compression());

app.use(
    helmet({
        crossOriginResourcePolicy: false,
    })
);

const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:5174',
    'https://expense-tracker-vija-apps.netlify.app',
];

app.use(
    cors({
        origin: function (origin, callback) {
            if (!origin) return callback(null, true);
            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }
            return callback(new Error('Not allowed by CORS'));
        },
        credentials: true,
    })
);

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: {
            code: 'RATE_LIMIT',
            message: 'Too many requests from this IP, please try again after 15 minutes',
        },
    },
});
app.use('/api', apiLimiter);

app.use(express.json({ limit: '1mb' }));

let cached = global.mongoose;
if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectToDatabase() {
    if (cached.conn) {
        return cached.conn;
    }

    if (!cached.promise) {
        cached.promise = mongoose
            .connect(process.env.MONGO_URI, {
                maxPoolSize: 20,
                minPoolSize: 2,
                serverSelectionTimeoutMS: 10000,
            })
            .then((mongooseConn) => mongooseConn);
    }
    cached.conn = await cached.promise;
    return cached.conn;
}

app.use('/api', userRouter);
app.use('/api/solution', solutionCardRouter);
app.use('/api/expense', expenseRouter);
app.use('/api/collected-cash', collectedCashRoutes);
app.use('/api', dashboardRouter);
app.use('/api/reports', reportRouter);

// JSON 404 for unknown API paths
app.use('/api', (req, res) => {
    res.status(404).json({
        success: false,
        error: {
            code: 'NOT_FOUND',
            message: `API route not found: ${req.method} ${req.originalUrl}`,
        },
    });
});

app.use(errorHandler);

const PORT = process.env.PORT || 5000;

connectToDatabase()
    .then(() => {
        console.log('MongoDB connected');
        const emailDiag = getEmailDiagnostics();
        console.log(`[Email] transport=${emailDiag.transport} sender=${emailDiag.sender} smtpLogin=${emailDiag.smtpLogin || 'n/a'}`);
        if (emailDiag.invalidFromConfig) {
            console.warn(
                '[Email] WARNING: EMAIL_FROM must not be @smtp-brevo.com. ' +
                    'Use a verified sender; keep @smtp-brevo.com as BREVO_SMTP_USER only.'
            );
        }
        if (!emailDiag.sender) {
            console.warn('[Email] WARNING: No valid EMAIL_FROM configured — outbound email will fail.');
        }
        if (emailDiag.smtpFallbackAvailable) {
            console.log('[Email] SMTP fallback enabled if Brevo API blocks server IP');
        }
        if (emailDiag.freeSenderWarning) {
            console.warn(
                '[Email] WARNING: EMAIL_FROM uses a free provider (@gmail.com etc). ' +
                    'Brevo may replace the sender or deliver poorly to external inboxes. ' +
                    'Verify sender in Brevo or use a custom domain for reliable delivery.'
            );
        }
        const frontendBase = (process.env.FRONTEND_BASE_URL || '').trim();
        if (!frontendBase) {
            console.warn(
                '[Email] WARNING: FRONTEND_BASE_URL is not set — links in share/welcome/OTP emails will be broken.'
            );
        } else if (/localhost|127\.0\.0\.1/i.test(frontendBase) && process.env.NODE_ENV === 'production') {
            console.warn(
                `[Email] WARNING: FRONTEND_BASE_URL is "${frontendBase}" in production — email links will point to localhost.`
            );
        } else {
            console.log(`[Email] FRONTEND_BASE_URL=${frontendBase}`);
        }
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });
