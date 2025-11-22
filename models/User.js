import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username: { type: String },
    email: { type: String, required: true, unique: true },
    password: { type: String },

    // Para login social
    googleId: { type: String },
    githubId: { type: String },

    // MFA
    mfaEnabled: { type: Boolean, default: false },
    mfaSecret: { type: String, default: "" },

    createdAt: { type: Date, default: Date.now }
});

// Export default CORRETO
const User = mongoose.model("User", userSchema);
export default User;
