import express from "express";
import requireLogin from "../middlewares/requireLogin.js"; // se você quiser separar
import Comment from "../models/Comment.js";
import Like from "../models/Like.js";

const router = express.Router();

/* ---------------------------
   Comentários
--------------------------- */
router.post("/comments", requireLogin, async (req, res) => {
  const { newsId, content } = req.body;
  if (!content) return res.status(400).json({ error: "Comentário vazio" });

  try {
    const comment = await Comment.create({
      newsId,
      userId: req.user._id,
      content
    });
    res.json(comment);
  } catch (err) {
    res.status(500).json({ error: "Erro ao criar comentário" });
  }
});

router.get("/comments/:newsId", async (req, res) => {
  const { newsId } = req.params;
  try {
    const comments = await Comment.find({ newsId }).populate("userId", "name");
    res.json(comments);
  } catch {
    res.status(500).json({ error: "Erro ao buscar comentários" });
  }
});

/* ---------------------------
   Curtidas
--------------------------- */
router.post("/likes", requireLogin, async (req, res) => {
  const { newsId } = req.body;
  try {
    const existing = await Like.findOne({ newsId, userId: req.user._id });
    if (existing) {
      await existing.deleteOne(); // descurtir
      return res.json({ liked: false });
    }

    await Like.create({ newsId, userId: req.user._id });
    res.json({ liked: true });
  } catch {
    res.status(500).json({ error: "Erro ao processar like" });
  }
});

router.get("/likes/:newsId", requireLogin, async (req, res) => {
  const { newsId } = req.params;
  try {
    const total = await Like.countDocuments({ newsId });
    const liked = await Like.exists({ newsId, userId: req.user._id });
    res.json({ total, liked: !!liked });
  } catch {
    res.status(500).json({ error: "Erro ao buscar likes" });
  }
});

export default router;
