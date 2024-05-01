const express = require("express");
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const User = require('./modal/User');
const middleware = require("./middleware/authentication");
require('dotenv').config();
const connectToDatabase = require('./config/db');

app.use(express.json());
app.use(cookieParser());

connectToDatabase();

app.get('/', (req, res)=>{
    res.status(200).send("Hello World");
})

app.post('/registration', async(req, res) => {
    try {
        const { username, email, password } = req.body;
        console.log(req.body);
        if (!username || !email || !password) {
            return res.status(400).json({ message: "Please provide username, email, and password" });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT));
        console.log(hashedPassword);

        const newUser = new User({
            username,
            email,
            password : hashedPassword,
        });

        await newUser.save();

        res.status(200).send('Successfully registered');
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});


app.post('/login', async(req,res)=>{
    try {
        const {email , password} = req.body;

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(400).json({ error: "Email not registered" });
        }

        const isPasswordValid = await bcrypt.compare(password, existingUser.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: "Invalid password" });
        }

        const accessToken  = jwt.sign({ userId: existingUser._id }, process.env.SECRET_KEY, { expiresIn: process.env.JWT_EXPIRATION });

        const refreshToken = jwt.sign({ userId: existingUser._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRATION });
        res.cookie('token', accessToken, { httpOnly: true });
        res.cookie('refreshToken', refreshToken, { httpOnly: true });
        res.json({ accessToken, refreshToken });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post('/token', async(req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const userId = decoded.userId;

        const accessToken = jwt.sign({ userId }, process.env.SECRETKEY, { expiresIn: process.env.JWT_EXPIRATION });

        res.cookie('token', accessToken, { httpOnly: true });

        res.json({ accessToken });
    } catch (error) {
        res.sendStatus(403);
    }
});

app.post('/dashboard' , middleware, (req, res) => {
    res.status(200).json({ message: 'Welcome to the dashboard!' });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token').json({ message: 'Logged out successfully' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
