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
// MONGODB
// ----------------------------
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB conectado ✅"))
  .catch((err) => console.log("Erro MongoDB:", err));

// ----------------------------
// MIDDLEWARES
// ----------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:3000", credentials: true }));

// ----------------------------
// SESSÃO
// ----------------------------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI, ttl: 14 * 24 * 60 * 60 }),
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
// THEME + USER GLOBAL
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

// Página home com notícias (autenticado)
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
// REDIRECIONAMENTOS DE LOGIN E FORGOT
// ----------------------------
app.get("/login", (req, res) => res.redirect("/auth/login"));
app.get("/forgot-password", (req, res) => res.redirect("/auth/forgot-password"));
app.get("/logout", (req, res) => res.redirect("/auth/logout"));

// ----------------------------
// SERVIDOR
// ----------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando em ${process.env.BASE_URL || "http://localhost"}:${PORT}`));
