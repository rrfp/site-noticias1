import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  googleId: String,
  githubId: String,
  mfaEnabled: { type: Boolean, default: false },
  mfaSecret: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

export default mongoose.model("User", UserSchema);
