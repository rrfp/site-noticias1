import express from "express";
import News from "../models/News.js"; // Modelo de notícias
import { isAuthenticated } from "../middlewares/authMiddleware.js"; // Middleware correto

const router = express.Router();

/* Curtir / Descurtir notícia */
router.post("/:id/like", isAuthenticated, async (req, res) => {
  try {
    const news = await News.findById(req.params.id);
    if (!news) return res.status(404).json({ error: "Notícia não encontrada" });

    const userId = req.user._id;

    if (news.likes.includes(userId)) news.likes.pull(userId);
    else news.likes.push(userId);

    await news.save();

    res.json({ success: true, likesCount: news.likes.length });
  } catch (err) {
    console.error("Erro ao curtir notícia:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

/* Adicionar comentário */
router.post("/:id/comment", isAuthenticated, async (req, res) => {
  try {
    const news = await News.findById(req.params.id);
    if (!news) return res.status(404).json({ error: "Notícia não encontrada" });

    const { text } = req.body;
    if (!text || text.trim() === "") return res.status(400).json({ error: "Comentário vazio" });

    const comment = {
      userId: req.user._id,
      username: req.user.name || req.user.email,
      text: text.trim(),
      createdAt: new Date()
    };

    news.comments.push(comment);
    await news.save();

    res.json({ success: true, comment, commentsCount: news.comments.length });
  } catch (err) {
    console.error("Erro ao adicionar comentário:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

export default router;
