import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import passport from "passport";
import path from "path";
import cors from "cors";
import MongoStore from "connect-mongo";
import cookieParser from "cookie-parser";
import axios from "axios";
import newsRoutes from "./routes/news.js";
// Rotas de autenticação
import authRoutes from "./routes/auth.js";

// __dirname no ES Module
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* --------------------------------------
   🔗 CONEXÃO COM MONGODB
-------------------------------------- */
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB conectado ✅"))
.catch(err => console.log("Erro MongoDB:", err));

/* --------------------------------------
   🧩 MIDDLEWARES
-------------------------------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


app.use(
  cors({
    origin: process.env.FRONTEND_URL || "https://site-noticias1.onrender.com",
    credentials: true,
  })
);

/* --------------------------------------
   🔐 SESSÃO
-------------------------------------- */
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      ttl: 14 * 24 * 60 * 60,
    }),
    cookie: {
      maxAge: 14 * 24 * 60 * 60 * 1000,
      sameSite: "lax",
    },
  })
);

/* --------------------------------------
   🔐 PASSPORT 
-------------------------------------- */
app.use(passport.initialize());
app.use(passport.session());

// IMPORTANTE: a configuração das estratégias está no auth.js
// então NÃO precisa de passport.js

/* --------------------------------------
   🎨 VIEW ENGINE + ESTÁTICOS
-------------------------------------- */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

/* --------------------------------------
   🔐 ROTAS DE AUTENTICAÇÃO
-------------------------------------- */
app.use("/auth", authRoutes);
app.use("/news", newsRoutes);


/* --------------------------------------
   🎨 THEME GLOBAL
-------------------------------------- */
app.use((req, res, next) => {
  res.locals.theme = req.cookies?.theme || "light";
  res.locals.user = req.user || null;
  next();
});

/* --------------------------------------
   📰 BUSCAR NOTÍCIAS
-------------------------------------- */
async function fetchNews(query = "tecnologia") {
  try {
    const apiKey = process.env.NEWS_API_KEY;
    const response = await axios.get(
      `https://newsapi.org/v2/everything?q=${encodeURIComponent(
        query
      )}&language=pt&pageSize=100&apiKey=${apiKey}`
    );

    return response.data.articles.map((a) => ({
      title: a.title,
      description: a.description || a.content,
      url: a.url,
      urlToImage: a.urlToImage,
      source: a.source.name,
    }));
  } catch (err) {
    console.error("Erro ao buscar notícias:", err.message);
    return [];
  }
}

/* --------------------------------------
   🏠 HOME
-------------------------------------- */
app.get("/", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.render("home", { articles: [], query: "" });
  }

  const articles = await fetchNews();
  res.render("home", { articles, query: "" });
});

/* --------------------------------------
   🔍 PESQUISA
-------------------------------------- */
app.get("/search", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");

  const q = req.query.q || "tecnologia";
  const articles = await fetchNews(q);

  res.render("home", { articles, query: q });
});

/* --------------------------------------
   🎨 ALTERAR TEMA
-------------------------------------- */
app.post("/set-theme", (req, res) => {
  const { theme } = req.body;

  if (!["light", "dark"].includes(theme)) {
    return res.status(400).json({ message: "Tema inválido" });
  }

  res.cookie("theme", theme, {
    httpOnly: false,
    maxAge: 365 * 24 * 60 * 60 * 1000,
  });

  res.json({ success: true, message: "Tema atualizado!" });
});

/* --------------------------------------
   🔓 LOGOUT
-------------------------------------- */
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);

    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.redirect("/");
    });
  });
});

/* --------------------------------------
   🚀 INICIAR SERVIDOR
-------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Servidor rodando em http://localhost:${PORT}`)
);
