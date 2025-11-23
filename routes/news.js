// routes/news.js
import express from "express";
import { requireLogin } from "../middlewares/authMiddleware.js";

const router = express.Router();

// Exemplo de armazenamento temporário (substitua pelo MongoDB depois)
let newsLikes = {};   // { newsId: quantidade }
let newsComments = {}; // { newsId: [{ user, comment }] }

/**
 * Curtir notícia
 * POST /api/news/like
 * Body: { newsId }
 */
router.post("/like", requireLogin, (req, res) => {
  const { newsId } = req.body;
  if (!newsId) return res.status(400).json({ success: false, message: "ID da notícia é obrigatório" });

  newsLikes[newsId] = (newsLikes[newsId] || 0) + 1;
  res.json({ success: true, likes: newsLikes[newsId] });
});

/**
 * Comentar notícia
 * POST /api/news/comment
 * Body: { newsId, comment }
 */
router.post("/comment", requireLogin, (req, res) => {
  const { newsId, comment } = req.body;
  if (!newsId || !comment) return res.status(400).json({ success: false, message: "ID e comentário são obrigatórios" });

  newsComments[newsId] = newsComments[newsId] || [];
  newsComments[newsId].push({ user: req.user.name, comment, date: new Date() });

  res.json({ success: true, comments: newsComments[newsId] });
});

/**
 * Obter comentários de uma notícia
 * GET /api/news/comments/:newsId
 */
router.get("/comments/:newsId", requireLogin, (req, res) => {
  const { newsId } = req.params;
  res.json({ comments: newsComments[newsId] || [] });
});

export default router;
