const mongoose = require('mongoose');

const BlacklistSchema = new mongoose.Schema({
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: '7d' },
});

module.exports = mongoose.model('Blacklist', BlacklistSchema);
