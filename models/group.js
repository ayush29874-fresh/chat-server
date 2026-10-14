const mongoose = require('mongoose');

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 40 },
  members: { type: [String], required: true, index: true },
  createdBy: { type: String, required: true },
}, { timestamps: true });

module.exports = mongoose.model('Group', groupSchema);
