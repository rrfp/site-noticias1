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

// BASE_URL dinâmica (local ou produção)
const isDeploy = process.env.NODE_ENV === "production";
const BASE_URL = isDeploy
  ? process.env.DEPLOY_BASE_URL
  : process.env.LOCAL_BASE_URL;

/* -------------------------------
   🔹 Middleware
--------------------------------*/
function requireLogin(req, res, next) {
  if (!req.user) return res.redirect("/auth/login");
  next();
}

/* -------------------------------
   🔹 STRATEGIES
--------------------------------*/
// GOOGLE
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

// GITHUB
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

/* -------------------------------
   🔹 SESSION
--------------------------------*/
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

/* -------------------------------
   🔹 ROTAS LOGIN SOCIAL
--------------------------------*/
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
    res.redirect("/auth/mfa-verify");
  }
);

/* -------------------------------
   🔹 LOGIN NORMAL
--------------------------------*/
router.get("/login", (req, res) =>
  res.render("login", { error: null, message: null, email: "", user: req.user, theme: req.cookies.theme || "light" })
);

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

/* -------------------------------
   🔹 REDEFINIÇÃO DE SENHA
--------------------------------*/
router.get("/forgot-password", (req, res) => {
  res.render("forgot-password", { error: null, message: null, theme: req.cookies.theme || "light" });
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render("forgot-password", { error: "Usuário não encontrado.", message: null, theme: req.cookies.theme || "light" });

  const token = crypto.randomBytes(20).toString("hex");
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hora
  await user.save();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  const resetLink = `${BASE_URL}/auth/reset-password/${token}`;
  const mailOptions = {
    to: user.email,
    from: process.env.EMAIL_USER,
    subject: "Redefinição de senha",
    text: `Você solicitou redefinição de senha. Clique aqui: ${resetLink}`,
  };

  transporter.sendMail(mailOptions, err => {
    if (err) console.error(err);
    res.render("forgot-password", { error: null, message: "Email de redefinição enviado!", theme: req.cookies.theme || "light" });
  });
});

router.get("/reset-password/:token", async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });
  if (!user) return res.send("Token inválido ou expirado.");
  res.render("reset-password", { error: null, token: req.params.token, theme: req.cookies.theme || "light" });
});

router.post("/reset-password/:token", async (req, res) => {
  const { password, confirmPassword } = req.body;
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });
  if (!user) return res.json({ success: false, message: "Token inválido ou expirado." });
  if (password !== confirmPassword) return res.json({ success: false, message: "Senhas não conferem." });

  const hash = await bcrypt.hash(password, 10);
  user.password = hash;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  res.json({ success: true, message: "Senha alterada com sucesso!" });
});

/* -------------------------------
   🔹 MFA
--------------------------------*/
router.get("/mfa-verify", (req, res) => {
  if (!req.session.tempUserId) return res.redirect("/auth/login");
  res.render("mfa-verify", { error: null, theme: req.cookies.theme || "light" });
});

router.post("/mfa/login", async (req, res) => {
  const { token } = req.body;
  if (!req.session.tempUserId) return res.redirect("/auth/login");
  const user = await User.findById(req.session.tempUserId);
  if (!user?.mfaEnabled) return res.render("mfa-verify", { error: "MFA não configurado.", theme: req.cookies.theme || "light" });
  const verified = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: "base32", token });
  if (!verified) return res.render("mfa-verify", { error: "Código MFA inválido.", theme: req.cookies.theme || "light" });
  req.login(user, err => {
    if (err) console.error(err);
    delete req.session.tempUserId;
    res.redirect("/");
  });
});

// GERA QR CODE SOMENTE NA PRIMEIRA VEZ
router.get("/mfa/setup", requireLogin, async (req, res) => {
  if (!req.user.mfaEnabled) {
    const secret = speakeasy.generateSecret({ name: "SeuSite - MFA" });
    const qrCodeImageUrl = await QRCode.toDataURL(secret.otpauth_url);
    req.session.tempMfaSecret = secret.base32;
    return res.render("mfa-setup", { qrCode: qrCodeImageUrl, error: null, theme: req.cookies.theme || "light" });
  } 
  // Usuário já configurou MFA
  res.redirect("/");
});

router.post("/mfa/verify", requireLogin, async (req, res) => {
  const { token } = req.body;
  const verified = speakeasy.totp.verify({ secret: req.session.tempMfaSecret, encoding: "base32", token });
  if (!verified) return res.render("mfa-setup", { qrCode: null, error: "Código inválido", theme: req.cookies.theme || "light" });
  const user = await User.findById(req.user.id);
  user.mfaEnabled = true;
  user.mfaSecret = req.session.tempMfaSecret;
  await user.save();
  delete req.session.tempMfaSecret;
  res.redirect("/");
});

/* -------------------------------
   🔹 LOGOUT
--------------------------------*/
router.get("/logout", (req, res) => {
  req.logout(err => {
    if (err) console.error(err);
    req.session.destroy(() => res.clearCookie("connect.sid") && res.redirect("/auth/login"));
  });
});

export default router;
export { requireLogin };
