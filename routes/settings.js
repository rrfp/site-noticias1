const express = require('express');
const router = express.Router();

router.post('/set-theme', (req, res) => {
    const { theme } = req.body;

    if (!['light', 'dark'].includes(theme)) {
        return res.status(400).json({ message: 'Tema inválido' });
    }

    res.cookie('theme', theme, {
        httpOnly: false,
        maxAge: 30 * 24 * 60 * 60 * 1000
    });

    res.json({ message: 'Tema atualizado' });
});

module.exports = router;
