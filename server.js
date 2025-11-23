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

// Rotas
import authRoutes, { requireLogin } from "./routes/auth.js";
import newsRoutes from "./routes/news.js";
import newsApiRoutes from "./routes/newsApi.js";

// __dirname no ES Module
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ----------------------------
// BASE_URL E MONGO DINÂMICOS
// ----------------------------
const IS_DEPLOY = !!process.env.PORT;
const PORT = process.env.PORT || process.env.LOCAL_PORT || 3000;
const MONGO_URI = IS_DEPLOY ? process.env.DEPLOY_MONGO_URI : process.env.LOCAL_MONGO_URI;

// BASE_URL local não deve duplicar a porta
const BASE_URL = IS_DEPLOY ? process.env.DEPLOY_BASE_URL : `${process.env.LOCAL_BASE_URL}:${PORT}`;
const LOG_URL = `${BASE_URL}`;

// ----------------------------
// MONGODB
// ----------------------------
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB conectado ✅"))
  .catch((err) => console.log("Erro MongoDB:", err));

// ----------------------------
// MIDDLEWARES
// ----------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS
app.use(cors({ origin: BASE_URL, credentials: true }));

// ----------------------------
// SESSÃO
// ----------------------------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI, ttl: 14 * 24 * 60 * 60 }),
    cookie: { maxAge: 14 * 24 * 60 * 60 * 1000, sameSite: "lax" },
  })
);

// ----------------------------
// PASSPORT
// ----------------------------
app.use(passport.initialize());
app.use(passport.session());

// ----------------------------
// VIEW ENGINE + ESTÁTICOS
// ----------------------------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// ----------------------------
// VARIÁVEIS GLOBAIS PARA VIEWS
// ----------------------------
app.use((req, res, next) => {
  res.locals.theme = req.cookies?.theme || "light";
  res.locals.user = req.user || null;
  next();
});

// ----------------------------
// ROTAS
// ----------------------------
app.use("/auth", authRoutes);
app.use("/api/news", requireLogin, newsRoutes);
app.use("/api/news-api", requireLogin, newsApiRoutes);

// ----------------------------
// REDIRECIONAMENTO HOME
// ----------------------------
app.get("/", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/auth/login");
  res.redirect("/home");
});

app.get("/home", requireLogin, async (req, res) => {
  const articles = await fetchNews();
  res.render("home", { articles, query: "" });
});

// ----------------------------
// FUNÇÃO PARA BUSCAR NOTÍCIAS
// ----------------------------
async function fetchNews(query = "tecnologia") {
  try {
    const apiKey = process.env.NEWS_API_KEY;
    const response = await axios.get(
      `https://newsapi.org/v2/everything?q=${encodeURIComponent(query)}&language=pt&pageSize=100&apiKey=${apiKey}`
    );
    return response.data.articles.map((a) => ({
      title: a.title,
      description: a.description || a.content,
      url: a.url,
      urlToImage: a.urlToImage,
      source: a.source.name,
      likes: [],
      comments: [],
      _id: a.title + Math.random(),
    }));
  } catch (err) {
    console.error("Erro ao buscar notícias:", err.message);
    return [];
  }
}

// ----------------------------
// SET THEME
// ----------------------------
app.post("/set-theme", (req, res) => {
  const { theme } = req.body;
  if (!["light", "dark"].includes(theme)) return res.status(400).json({ message: "Tema inválido" });
  res.cookie("theme", theme, { httpOnly: false, maxAge: 365 * 24 * 60 * 60 * 1000 });
  res.json({ success: true, message: "Tema atualizado!" });
});

// ----------------------------
// REDIRECIONAMENTOS DE LOGIN
// ----------------------------
app.get("/login", (req, res) => res.redirect("/auth/login"));
app.get("/forgot-password", (req, res) => res.redirect("/auth/forgot-password"));
app.get("/logout", (req, res) => res.redirect("/auth/logout"));
app.get("/register", (req, res) => res.redirect("/auth/register"));


// ----------------------------
// SERVIDOR
// ----------------------------
app.listen(PORT, () => console.log(`Servidor rodando em ${LOG_URL}`));
