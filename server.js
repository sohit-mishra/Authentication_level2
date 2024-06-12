require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const connectToDatabase = require('./config/db');
const authRoutes = require('./routes/auth');

const app = express();
app.use(express.json());
app.use(cookieParser());

connectToDatabase();

app.get('/', (req, res) => {
    res.status(200).send("Hello World");
});

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
