router.post('/set-theme', (req, res) => {
    const { theme } = req.body;

    if (!['light', 'dark'].includes(theme)) {
        return res.status(400).json({ message: 'Tema inválido' });
    }

    // salva o cookie
    res.cookie('theme', theme, {
        httpOnly: false, 
        maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.json({ message: 'Tema atualizado' });
});


const express = require('express');
const router = express.Router();
const axios = require('axios');

const fallbackNews = [
  { title: "Notícia de teste 1", description: "Descrição da notícia 1", url: "#", urlToImage: null },
  { title: "Notícia de teste 2", description: "Descrição da notícia 2", url: "#", urlToImage: null }
];

router.get('/', async (req, res) => {
  try {
    const apiKey = process.env.NEWS_API_KEY;
    const response = await axios.get(
      `https://newsapi.org/v2/everything?q=tecnologia&language=pt&apiKey=${apiKey}`
    );

    let news = response.data.articles.map(a => ({
      title: a.title,
      description: a.description || a.content,
      url: a.url,
      urlToImage: a.urlToImage,
      source: a.source.name
    }));

    if (!news || news.length === 0) news = fallbackNews;

    res.json(news);
  } catch (err) {
    console.error("Erro ao carregar notícias da API:", err.message);
    res.json(fallbackNews);
  }
});

module.exports = router;
