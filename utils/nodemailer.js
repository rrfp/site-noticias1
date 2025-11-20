// utils/nodemailer.js
const nodemailer = require("nodemailer");

// Transporter (para Gmail)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,  // seu email
    pass: process.env.EMAIL_PASS   // app password do Gmail
  }
});

// Função para enviar email de recuperação
async function sendPasswordResetEmail(to, token) {
  const resetUrl = `${process.env.BASE_URL}/reset-password/${token}`;

  await transporter.sendMail({
    from: `"Suporte Notícias" <${process.env.EMAIL_USER}>`,
    to,
    subject: "Recuperação de Senha",
    html: `
      <h2>Recuperação de Senha</h2>
      <p>Clique no link abaixo para redefinir sua senha:</p>

      <a href="${resetUrl}" 
         style="padding: 10px 20px; background: #007bff; color: white; 
         border-radius: 5px; text-decoration: none;">
        Redefinir Senha
      </a>

      <p style="margin-top:15px;">
        Se você não solicitou isso, ignore este email.
      </p>
    `
  });
}

module.exports = { sendPasswordResetEmail };
