import express from "express";
import bcrypt from "bcrypt";
import passport from "passport";
import User from "../models/User.js";  // ajuste o caminho se necessário
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";

const router = express.Router();

/* ------------------ LOGIN SOCIAL ------------------ */

// Passport Google
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Buscar ou criar usuário
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = await User.create({
        name: profile.displayName,
        email: profile.emails[0].value,
        googleId: profile.id
      });
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// Passport GitHub
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    if (!user) {
      user = await User.create({
        name: profile.displayName || profile.username,
        email: profile.emails?.[0]?.value || `${profile.username}@github.com`,
        githubId: profile.id
      });
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// Serialização
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// --- Rotas Google ---
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => { res.redirect('/'); }
);

// --- Rotas GitHub ---
router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));
router.get('/github/callback', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => { res.redirect('/'); }
);

/* ------------------ RESET PASSWORD EXISTENTE ------------------ */

router.get("/reset-password/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.render("reset-password", {
        error: "Token inválido ou expirado.",
        token: null
      });
    }

    res.render("reset-password", { token });
  } catch (error) {
    console.log(error);
    res.render("reset-password", {
      error: "Erro ao validar token.",
      token: null
    });
  }
});

router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("reset-password", {
      error: "As senhas não coincidem.",
      token
    });
  }

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.render("reset-password", {
        error: "Token inválido ou expirado.",
        token: null
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    await user.save();

    res.render("login", {
      message: "Senha redefinida com sucesso! Faça login."
    });

  } catch (error) {
    console.log(error);
    res.render("reset-password", {
      error: "Erro ao atualizar a senha.",
      token
    });
  }
});

export default router;
