const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  name: { type: String },

  // Login social
  googleId: { type: String },
  githubId: { type: String },

  // Recuperação de senha
  resetToken: { type: String, default: null },
  resetTokenExpires: { type: Date, default: null }
});

// Exporta o modelo User
module.exports = mongoose.model("User", UserSchema);
