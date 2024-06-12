const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../modal/User');
const Blacklist = require('../modal/blacklisted');
const auth = require('../middleware/authentication');
router.use(express.json());

const router = express.Router();


router.post('/registration', async (req, res) => {
    try {
        console.log(res.body);
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ message: "Please provide username, email, and password" });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT));

        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(200).send('Successfully registered');
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(400).json({ error: "Email not registered" });
        }

        const isPasswordValid = await bcrypt.compare(password, existingUser.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: "Invalid password" });
        }

        const accessToken = jwt.sign({ userId: existingUser._id }, process.env.SECRET_KEY, { expiresIn: process.env.JWT_EXPIRATION });
        const refreshToken = jwt.sign({ userId: existingUser._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRATION });

        res.cookie('token', accessToken, { httpOnly: true });
        res.cookie('refreshToken', refreshToken, { httpOnly: true });
        res.json({ accessToken, refreshToken });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Token Refresh
router.post('/token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const userId = decoded.userId;

        const accessToken = jwt.sign({ userId }, process.env.SECRET_KEY, { expiresIn: process.env.JWT_EXPIRATION });

        res.cookie('token', accessToken, { httpOnly: true });
        res.json({ accessToken });
    } catch (error) {
        res.sendStatus(403);
    }
});

// Dashboard
router.post('/dashboard', auth, (req, res) => {
    res.status(200).json({ message: 'Welcome to the dashboard!' });
});

// Logout
router.get('/logout', async (req, res) => {
    const token = req.cookies.token;
    try {
        await new Blacklist({ token }).save();
        res.clearCookie('token').clearCookie('refreshToken').json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Refresh Token
router.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).send('No refresh token provided.');

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(400).send('Invalid refresh token.');

        const payload = { userId: user._id };
        const token = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: process.env.JWT_EXPIRATION });
        res.send({ token });
    } catch (err) {
        res.status(400).send('Invalid refresh token.');
    }
});

module.exports = router;
