import mongoose from "mongoose";

const commentSchema = new mongoose.Schema({
  newsId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model("Comment", commentSchema);
