const nodemailer = require('nodemailer');
require('dotenv').config();


const transporter = nodemailer.createTransport({
    service: 'Gmail', // or your email provider
    auth: {
        user: process.env.EMAIL_USER,       // your email
        pass: process.env.EMAIL_PASSWORD,   // your email password or app-specific password
    }
});

const sendEmail = async (to, subject, html) => {
    const mailOptions = {
        from: `"Vinayaka Chavithi Tracker" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html,
        // You can add html here for a richer email template as well
    };

    await transporter.sendMail(mailOptions);
};

module.exports = { sendEmail };
