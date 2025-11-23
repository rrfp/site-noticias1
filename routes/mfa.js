import express from "express";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import User from "../models/User.js";

const router = express.Router();

/* --------------------------
   REQUER LOGIN PARA CONFIGURAR
--------------------------- */
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.redirect("/login");
}

/* -----------------------------------------
   1) GERAR QR CODE TOTP PARA ATIVAR NO CELULAR
----------------------------------------- */
router.get("/setup", ensureAuth, async (req, res) => {
  const secret = speakeasy.generateSecret({
    name: "Site Notícias - MFA",
  });

  const qrDataURL = await QRCode.toDataURL(secret.otpauth_url);

  // salva secret temporária na sessão
  req.session.tempMfaSecret = secret.base32;

  res.render("mfa/setup", {
    qrCode: qrDataURL,
    secret: secret.base32
  });
});

/* -----------------------------------------
   2) VALIDAR O CÓDIGO DIGITADO NO CELULAR
----------------------------------------- */
router.post("/setup", ensureAuth, async (req, res) => {
  const { token } = req.body;
  const secret = req.session.tempMfaSecret;

  const ok = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token
  });

  if (!ok) {
    return res.render("mfa/setup", {
      error: "Código inválido. Tente novamente.",
      qrCode: null
    });
  }

  // salvar no banco
  const user = await User.findById(req.user._id);
  user.mfaEnabled = true;
  user.mfaSecret = secret;
  await user.save();

  delete req.session.tempMfaSecret;

  res.redirect("/");
});

/* -----------------------------------------
   3) VALIDAÇÃO DO MFA APÓS LOGIN
----------------------------------------- */
router.get("/validate", async (req, res) => {
  if (!req.session.tempUserId) return res.redirect("/login");

  res.render("mfa/validate");
});

router.post("/validate", async (req, res) => {
  const { token } = req.body;

  const user = await User.findById(req.session.tempUserId);
  if (!user) return res.redirect("/login");

  const ok = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: "base32",
    token
  });

  if (!ok) {
    return res.render("mfa/validate", {
      error: "Código incorreto!"
    });
  }

  // login completo agora
  req.login(user, (err) => {
    if (err) return res.redirect("/login");
    delete req.session.tempUserId;
    return res.redirect("/");
  });
});

export default router;
