// routes/newsApi.js
import express from "express";
import axios from "axios";
import { requireLogin } from "../middlewares/authMiddleware.js";

const router = express.Router();

/**
 * GET /api/news-api?query=palavra
 * Retorna notícias externas da NewsAPI
 */
router.get("/", requireLogin, async (req, res) => {
  const query = req.query.query || "tecnologia";
  const apiKey = process.env.NEWS_API_KEY;

  try {
    const response = await axios.get(
      `https://newsapi.org/v2/everything?q=${encodeURIComponent(query)}&language=pt&pageSize=20&apiKey=${apiKey}`
    );

    const articles = response.data.articles.map(a => ({
      title: a.title,
      description: a.description || a.content,
      url: a.url,
      urlToImage: a.urlToImage,
      source: a.source.name,
    }));

    res.json({ success: true, articles });
  } catch (err) {
    console.error("Erro NewsAPI:", err.message);
    res.status(500).json({ success: false, message: "Erro ao buscar notícias" });
  }
});

export default router;
