const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  from: { type: String, required: true, index: true },
  to:   { type: String, required: true, index: true },
  text: { type: String, required: true, maxlength: 1000 },
  conversationId: { type: String, required: true },
}, { timestamps: true });

messageSchema.index({ conversationId: 1, createdAt: 1 });
messageSchema.statics.convoId = (a, b) => [a, b].sort().join(':');

module.exports = mongoose.model('Message', messageSchema);