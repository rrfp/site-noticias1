import mongoose from "mongoose";

const NewsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    username: String,
    text: String,
    createdAt: { type: Date, default: Date.now }
  }]
});

export default mongoose.model("News", NewsSchema);
