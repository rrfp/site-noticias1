import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bcrypt from "bcryptjs";
import passport from "passport";
import User from "../models/User.js";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import crypto from "crypto";
import nodemailer from "nodemailer";

const router = express.Router();

// ----------------------------
// MIDDLEWARE
// ----------------------------
function requireLogin(req, res, next) {
  if (!req.user) return res.redirect("/auth/login");
  next();
}

// ----------------------------
// BASE URL (local vs produção)
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

// ----------------------------
// GOOGLE STRATEGY
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/auth/google/callback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOne({ googleId: profile.id });
          if (!user) {
            user = await User.findOne({ email: profile.emails[0].value });
            if (user) {
              user.googleId = profile.id;
              await user.save();
            } else {
              user = await User.create({
                name: profile.displayName,
                email: profile.emails[0].value,
                googleId: profile.id,
              });
            }
          }
          return done(null, user);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );
}

// ----------------------------
// GITHUB STRATEGY
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/auth/github/callback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOne({ githubId: profile.id });
          if (!user) {
            user = await User.findOne({ email: profile.emails?.[0]?.value || `${profile.username}@github.com` });
            if (user) {
              user.githubId = profile.id;
              await user.save();
            } else {
              user = await User.create({
                name: profile.displayName || profile.username,
                email: profile.emails?.[0]?.value || `${profile.username}@github.com`,
                githubId: profile.id,
              });
            }
          }
          return done(null, user);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );
}

// ----------------------------
// SESSION
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ----------------------------
// ROTAS LOGIN SOCIAL
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/login" }),
  async (req, res) => {
    if (!req.user) return res.redirect("/auth/login");
    if (!req.user.mfaEnabled) return res.redirect("/auth/mfa/setup");
    req.session.tempUserId = req.user._id;
    res.redirect("/auth/mfa-verify");
  }
);

router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));
router.get(
  "/github/callback",
  passport.authenticate("github", { failureRedirect: "/auth/login" }),
  async (req, res) => {
    if (!req.user) return res.redirect("/auth/login");
    if (!req.user.mfaEnabled) return res.redirect("/auth/mfa/setup");
    req.session.tempUserId = req.user._id;
    req.logout(err => {
      if (err) console.error(err);
      res.redirect("/auth/mfa-verify");
    });
  }
);

// ----------------------------
// LOGIN NORMAL
router.get("/login", (req, res) =>
  res.render("login", { error: null, message: null, email: "", user: req.user, theme: req.cookies.theme || "light" })
);

// POST login normal + MFA (mantém igual)
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.render("login", { error: "Usuário não encontrado.", email, user: null, theme: req.cookies.theme || "light" });
    if (!user.password) return res.render("login", { error: "Esta conta permite apenas login social.", email, user: null, theme: req.cookies.theme || "light" });
    const passwordOk = await bcrypt.compare(password, user.password);
    if (!passwordOk) return res.render("login", { error: "Senha incorreta.", email, user: null, theme: req.cookies.theme || "light" });
    if (user.mfaEnabled) {
      req.session.tempUserId = user._id;
      return res.redirect("/auth/mfa-verify");
    }
    req.login(user, err => {
      if (err) console.error(err);
      res.redirect("/");
    });
  } catch (err) {
    console.error(err);
    res.render("login", { error: "Erro no login.", email, user: null, theme: req.cookies.theme || "light" });
  }
});

// ----------------------------
// LOGOUT
router.get("/logout", (req, res) => {
  req.logout(err => {
    if (err) console.error(err);
    req.session.destroy(() => res.clearCookie("connect.sid") && res.redirect("/auth/login"));
  });
});

export default router;
export { requireLogin };
