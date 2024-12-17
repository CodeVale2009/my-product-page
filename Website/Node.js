const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();

// Middleware to parse JSON
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/authExample', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Define User Schema
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    verified: { type: Boolean, default: false },
    verificationCode: String
});

// User Model
const User = mongoose.model('User', UserSchema);

// Create Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your-email@gmail.com', // your email
        pass: 'your-email-password'   // your email password
    }
});

// Sign Up Route
app.post('/auth', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.json({ status: 'error', message: 'User already exists. Please login.' });
        }

        // Hash password before storing
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate verification code
        const verificationCode = Math.floor(Math.random() * 1000000);

        // Create new user
        const newUser = new User({
            email,
            password: hashedPassword,
            verificationCode
        });

        await newUser.save();

        // Send verification email
        const mailOptions = {
            from: 'your-email@gmail.com',
            to: email,
            subject: 'Verify your email',
            text: `Your verification code is: ${verificationCode}`
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return res.json({ status: 'error', message: 'Failed to send verification email' });
            }
            res.json({ status: 'success', message: 'User created, please check your email for verification code' });
        });
    } catch (error) {
        res.json({ status: 'error', message: 'Error signing up. Try again later.' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ status: 'error', message: 'User not found' });
        }

        // Check if user is verified
        if (!user.verified) {
            return res.json({ status: 'error', message: 'Please verify your email before logging in' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({ status: 'error', message: 'Invalid password' });
        }

        // Create JWT token
        const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });

        res.json({ status: 'success', message: 'Login successful', token });
    } catch (error) {
        res.json({ status: 'error', message: 'Error logging in. Try again later.' });
    }
});

// Verify Email Route (called when user enters verification code)
app.post('/verify-email', async (req, res) => {
    const { email, code } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ status: 'error', message: 'User not found' });
        }

        if (user.verificationCode === code) {
            user.verified = true;
            await user.save();
            res.json({ status: 'success', message: 'Email verified successfully!' });
        } else {
            res.json({ status: 'error', message: 'Invalid verification code' });
        }
    } catch (error) {
        res.json({ status: 'error', message: 'Error verifying email' });
    }
});

// Start server
app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});
