import express from "express";
import News from "../models/News.js";
import { requireLogin } from "./auth.js"; // seu middleware de autenticação

const router = express.Router();

// Listar todas notícias
router.get("/", async (req, res) => {
  try {
    const newsList = await News.find().sort({ createdAt: -1 });
    res.render("news", {
      newsList,
      user: req.user,
      theme: req.cookies.theme || "light"
    });
  } catch (err) {
    res.status(500).send("Erro ao buscar notícias");
  }
});

// Curtir / descurtir notícia
router.post("/:id/like", requireLogin, async (req, res) => {
  try {
    const news = await News.findById(req.params.id);
    if (!news) return res.status(404).json({ error: "Notícia não encontrada" });

    const userId = req.user._id;

    if (!news.likes) news.likes = [];
    if (news.likes.includes(userId)) {
      news.likes.pull(userId); // descurtir
    } else {
      news.likes.push(userId); // curtir
    }

    await news.save();
    res.json({ likesCount: news.likes.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao curtir notícia" });
  }
});

// Adicionar comentário
router.post("/:id/comment", requireLogin, async (req, res) => {
  try {
    const news = await News.findById(req.params.id);
    if (!news) return res.status(404).json({ error: "Notícia não encontrada" });

    const { text } = req.body;
    if (!text) return res.status(400).json({ error: "Comentário vazio" });

    if (!news.comments) news.comments = [];
    const comment = {
      userId: req.user._id,
      username: req.user.name,
      text,
      createdAt: new Date()
    };
    news.comments.push(comment);

    await news.save();
    res.json({ comment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao adicionar comentário" });
  }
});

export default router;
