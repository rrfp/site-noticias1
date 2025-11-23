import express from "express";
import News from "../models/News.js";
import { requireLogin } from "./auth.js"; // seu middleware de login

const router = express.Router();

// Curtir notícia
router.post("/news/:id/like", requireLogin, async (req, res) => {
  const news = await News.findById(req.params.id);
  if (!news) return res.status(404).json({ error: "Notícia não encontrada" });

  const userId = req.user._id;
  if (news.likes.includes(userId)) {
    news.likes.pull(userId); // descurtir
  } else {
    news.likes.push(userId);
  }
  await news.save();

  res.json({ likesCount: news.likes.length });
});

// Adicionar comentário
router.post("/news/:id/comment", requireLogin, async (req, res) => {
  const news = await News.findById(req.params.id);
  if (!news) return res.status(404).json({ error: "Notícia não encontrada" });

  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "Comentário vazio" });

  news.comments.push({
    userId: req.user._id,
    username: req.user.name,
    text
  });

  await news.save();
  res.json({ comment: news.comments[news.comments.length - 1] });
});

export default router;
