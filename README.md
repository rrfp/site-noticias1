Passos rápidos:
1. Copie este projeto para a sua máquina.
2. Crie um arquivo .env com os valores em .env.example.
- Gere DATA_KEY: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
3. Instale dependências: npm install
4. Rodar em dev: npm run dev
5. Abra http://localhost:3000

Para deploy no Render:
- Suba este repositório no GitHub.
- Crie um Web Service no Render apontando para o repo.
- Configure as environment variables no painel do Render (MONGO_URI, DATA_KEY, etc).
- Configure os Redirect URIs no Google Cloud Console e GitHub para: https://SEU-SITE.onrender.com/auth/google/callback e /auth/github/callback

# 📰 News Site com Login e Criptografia


## Como rodar localmente
```bash
npm install
cp .env.example .env # configure suas variáveis

🔧 O que fazer:

Entre na pasta news-site:
cd news-site

Confira se o package.json está lá:
dir

Se aparecer o package.json, então rode:
npm install

Depois, para iniciar o site:
npm run dev