require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const cors = require('cors');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

// Email (recuperação de senha)
const { sendPasswordResetEmail } = require('./utils/nodemailer');

const User = require('./models/User');
require('./passport')(passport);

const app = express();

// -----------------------------
// 🔗 CONEXÃO MONGODB
// -----------------------------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB conectado ✅"))
.catch(err => console.log("Erro MongoDB:", err));

// -----------------------------
// 🧩 MIDDLEWARES
// -----------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));



// Salvar tema via cookie
app.post("/set-theme", (req, res) => {
  const { theme } = req.body;

  if (!theme) {
    return res.status(400).json({ error: "Tema não informado" });
  }

  // salva cookie por 30 dias
  res.cookie("theme", theme, {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: false, 
  });

  return res.json({ success: true });
});


// -----------------------------
// 🔐 SESSÃO
// -----------------------------
app.use(session({
  secret: process.env.SESSION_SECRET || 'secretkey',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    ttl: 14 * 24 * 60 * 60
  }),
  cookie: { maxAge: 14 * 24 * 60 * 60 * 1000, sameSite: 'lax' }
}));

app.use(passport.initialize());
app.use(passport.session());

// -----------------------------
// 🎨 VIEW ENGINE + ARQUIVOS ESTÁTICOS
// -----------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// -----------------------------
// 🎨 TEMA GLOBAL
// -----------------------------
app.use((req, res, next) => {
  res.locals.theme = req.cookies?.theme || 'light';
  res.locals.user = req.user || null;
  next();
});

// -----------------------------
// 📰 FUNÇÃO PARA BUSCAR NOTÍCIAS
// -----------------------------
async function fetchNews(query = 'tecnologia') {
  try {
    const apiKey = process.env.NEWS_API_KEY;
    const pageSize = 100;

    const response = await axios.get(
      `https://newsapi.org/v2/everything?q=${encodeURIComponent(query)}&language=pt&pageSize=${pageSize}&apiKey=${apiKey}`
    );

    return response.data.articles.map(a => ({
      title: a.title,
      description: a.description || a.content,
      url: a.url,
      urlToImage: a.urlToImage,
      source: a.source.name
    }));

  } catch (err) {
    console.error("Erro ao buscar notícias:", err.message);
    return [];
  }
}

// -----------------------------
// 🏠 HOME
// -----------------------------
app.get('/', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.render('home', { articles: [], query: "" });
  }

  const articles = await fetchNews();
  res.render('home', { articles, query: "" });
});

// -----------------------------
// 🔍 PESQUISA
// -----------------------------
app.get('/search', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }

  const q = req.query.q || 'tecnologia';
  const articles = await fetchNews(q);
  res.render('home', { articles, query: q });
});

// -----------------------------
// 🔐 LOGIN
// -----------------------------
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user) => {
    if (err) return next(err);
    if (!user) return res.redirect('/login');

    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});

// -----------------------------
// 📝 REGISTRO
// -----------------------------
app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser)
      return res.json({ success: false, message: "❌ Email já está em uso." });

    const hashed = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashed,
      name: name || email
    });

    await user.save();
    return res.json({ success: true, message: "✅ Cadastro realizado com sucesso!" });

  } catch (err) {
    console.error("Erro no registro:", err);
    return res.json({ success: false, message: "❌ Erro no servidor. Tente novamente." });
  }
});

// -----------------------------
// 🔑 RECUPERAÇÃO DE SENHA — SOLICITAR
// -----------------------------
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user)
    return res.json({ success: true, message: "Se o email existir, enviamos um link." });

  const token = crypto.randomBytes(32).toString("hex");

  user.resetToken = token;
  user.resetTokenExpires = Date.now() + 1000 * 60 * 15;
  await user.save();

  await sendPasswordResetEmail(email, token);

  res.json({ success: true, message: "Email enviado! Verifique sua caixa de entrada." });
});

// -----------------------------
// 🔑 RECUPERAÇÃO — FORMULÁRIO
// -----------------------------
app.get('/reset-password/:token', async (req, res) => {
  const user = await User.findOne({
    resetToken: req.params.token,
    resetTokenExpires: { $gt: Date.now() }
  });

  if (!user) return res.send("❌ Token inválido ou expirado.");

  res.render('reset-password', { token: req.params.token });
});

// -----------------------------
// 🔑 RECUPERAÇÃO — NOVA SENHA
// -----------------------------
app.post('/reset-password/:token', async (req, res) => {
  const user = await User.findOne({
    resetToken: req.params.token,
    resetTokenExpires: { $gt: Date.now() }
  });

  if (!user)
    return res.json({ success: false, message: "Token expirado. Solicite novamente." });

  const hashed = await bcrypt.hash(req.body.password, 10);

  user.password = hashed;
  user.resetToken = undefined;
  user.resetTokenExpires = undefined;

  await user.save();

  res.json({ success: true, message: "Senha alterada! Você já pode entrar." });
});

// -----------------------------
// 🎨 ALTERAR TEMA
// -----------------------------
app.post('/set-theme', (req, res) => {
  const { theme } = req.body;

  if (!['light', 'dark'].includes(theme)) {
    return res.status(400).json({ message: "Tema inválido" });
  }

  res.cookie('theme', theme, {
    httpOnly: false,
    maxAge: 365 * 24 * 60 * 60 * 1000
  });

  res.json({ success: true, message: "Tema atualizado!" });
});

// -----------------------------
// 🔓 LOGOUT
// -----------------------------
app.get('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });
});

// -----------------------------
// 🚀 INICIAR SERVIDOR
// -----------------------------
const PORT = process.env.PORT || 3000;

// -----------------------------
// 🔗 LOGIN GOOGLE
// -----------------------------
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/');
  }
);

// -----------------------------
// 🔗 LOGIN GITHUB
// -----------------------------
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
