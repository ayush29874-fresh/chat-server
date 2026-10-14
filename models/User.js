const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: /^[a-z0-9_]{3,20}$/,
  },
  passwordHash: { type: String, required: true },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);