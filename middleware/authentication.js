const jwt = require('jsonwebtoken');
const User = require('../modal/User');
require('dotenv').config();

const authenticateUser = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ error: 'Access denied, no token provided' });
        }

        const decoded = jwt.verify(token, process.env.SECERTKEY);
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};

module.exports = authenticateUser;
