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

/* ----------------------------------------------------
   🔹 Middleware
---------------------------------------------------- */
function requireLogin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Não autenticado" });
  next();
}

/* ----------------------------------------------------
   🔹 STRATEGIES
---------------------------------------------------- */
// GOOGLE
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOne({ googleId: profile.id });
          if (!user) {
            user = await User.create({
              name: profile.displayName,
              email: profile.emails[0].value,
              googleId: profile.id,
            });
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
        callbackURL: process.env.GITHUB_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOne({ githubId: profile.id });
          if (!user) {
            user = await User.create({
              name: profile.displayName || profile.username,
              email: profile.emails?.[0]?.value || `${profile.username}@github.com`,
              githubId: profile.id,
            });
          }
          return done(null, user);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );
}

/* ----------------------------------------------------
   🔹 SESSION
---------------------------------------------------- */
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

/* ----------------------------------------------------
   🔹 ROTAS SOCIAIS
---------------------------------------------------- */
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  async (req, res) => {
    if (!req.user.mfaEnabled) return res.redirect("/auth/mfa/setup");
    req.session.tempUserId = req.user._id;
    req.logout(() => res.redirect("/auth/mfa-verify"));
  }
);

router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));
router.get(
  "/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  async (req, res) => {
    if (!req.user.mfaEnabled) return res.redirect("/auth/mfa/setup");
    req.session.tempUserId = req.user._id;
    req.logout(() => res.redirect("/auth/mfa-verify"));
  }
);

/* ----------------------------------------------------
   🔹 LOGIN NORMAL
---------------------------------------------------- */
router.get("/login", (req, res) => {
  res.render("login", {
    error: null,
    message: null,
    email: "",
    user: req.user,
    theme: req.cookies.theme || "light"
  });
});

router.post("/login", async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.render("login", { error: "Usuário não encontrado.", email, user: null, theme: req.cookies.theme || "light" });

    if (!user.password) return res.render("login", { error: "Esta conta permite apenas login social.", email, user: null, theme: req.cookies.theme || "light" });

    const passwordOK = await bcrypt.compare(password, user.password);
    if (!passwordOK) return res.render("login", { error: "Senha incorreta.", email, user: null, theme: req.cookies.theme || "light" });

    if (user.mfaEnabled) {
      req.session.tempUserId = user._id;
      return res.redirect("/auth/mfa-verify");
    }

    // Primeiro login → setup MFA
    req.login(user, (err) => {
      if (err) return next(err);
      if (!user.mfaEnabled) return res.redirect("/auth/mfa/setup");
      res.redirect("/");
    });
  } catch (err) {
    console.error(err);
    res.render("login", { error: "Erro no login.", email, user: null, theme: req.cookies.theme || "light" });
  }
});

/* ----------------------------------------------------
   🔹 MFA
---------------------------------------------------- */
router.get("/mfa-verify", (req, res) => {
  if (!req.session.tempUserId) return res.redirect("/login");
  res.render("mfa-verify", { error: null, theme: req.cookies.theme || "light" });
});

router.post("/mfa/login", async (req, res) => {
  const { token } = req.body;
  if (!req.session.tempUserId) return res.redirect("/login");

  const user = await User.findById(req.session.tempUserId);
  if (!user?.mfaEnabled) return res.render("mfa-verify", { error: "MFA não configurado.", theme: req.cookies.theme || "light" });

  const verified = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: "base32", token });
  if (!verified) return res.render("mfa-verify", { error: "Código MFA inválido.", theme: req.cookies.theme || "light" });

  req.login(user, (err) => {
    if (err) return res.render("mfa-verify", { error: "Erro ao autenticar.", theme: req.cookies.theme || "light" });
    delete req.session.tempUserId;
    res.redirect("/");
  });
});

router.get("/mfa/setup", requireLogin, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ name: "SeuSite - MFA" });
    const qrCodeImageUrl = await QRCode.toDataURL(secret.otpauth_url);
    req.session.tempMfaSecret = secret.base32;
    res.render("mfa-setup", { qrCode: qrCodeImageUrl, error: null, theme: req.cookies.theme || "light" });
  } catch {
    res.status(500).render("mfa-setup", { qrCode: null, error: "Erro ao gerar MFA", theme: req.cookies.theme || "light" });
  }
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

/* ----------------------------------------------------
   🔹 ESQUECEU SENHA / RESET
---------------------------------------------------- */
// Formulário de solicitação
router.get("/forgot-password", (req, res) => {
  res.render("forgot-password", { error: null, message: null, theme: req.cookies.theme || "light" });
});

// Enviar link de redefinição
// Enviar link de redefinição (corrigido para JSON)
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "E-mail não encontrado." });

    const token = crypto.randomBytes(32).toString("hex");
    user.resetToken = token;
    user.resetTokenExpires = Date.now() + 3600000; // 1 hora
    await user.save();

    // Envio de e-mail
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    const resetUrl = `${process.env.FRONTEND_URL || "http://localhost:3000"}/auth/reset-password/${token}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Redefinição de senha",
      html: `<p>Clique no link abaixo para redefinir sua senha:</p><a href="${resetUrl}">${resetUrl}</a>`
    });

    res.json({ success: true, message: "E-mail enviado! Verifique sua caixa de entrada." });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Erro ao processar pedido." });
  }
});


// Resetar senha via token
router.get("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const user = await User.findOne({ resetToken: token, resetTokenExpires: { $gt: Date.now() } });
  if (!user) return res.render("reset-password", { error: "Token inválido ou expirado.", token: null, theme: req.cookies.theme || "light" });
  res.render("reset-password", { token, theme: req.cookies.theme || "light" });
});

router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) return res.render("reset-password", { error: "As senhas não coincidem.", token, theme: req.cookies.theme || "light" });

  const user = await User.findOne({ resetToken: token, resetTokenExpires: { $gt: Date.now() } });
  if (!user) return res.render("reset-password", { error: "Token inválido ou expirado.", token: null, theme: req.cookies.theme || "light" });

  user.password = await bcrypt.hash(password, 10);
  user.resetToken = undefined;
  user.resetTokenExpires = undefined;
  await user.save();

  res.render("login", { message: "Senha redefinida com sucesso!", error: null, email: user.email, user: null, theme: req.cookies.theme || "light" });
});

/* ----------------------------------------------------
   🔹 LOGOUT
---------------------------------------------------- */
router.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.redirect("/");
    });
  });
});

export default router;
export { requireLogin };
