// middlewares/authMiddleware.js

/**
 * Middleware para rotas que renderizam páginas (home, dashboard, etc.)
 * Redireciona para "/" caso o usuário não esteja logado
 */
export function requireLoginPage(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/");
}

/**
 * Middleware para rotas de API
 * Retorna JSON com erro 401 caso não esteja logado
 */
export function requireLoginAPI(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ success: false, message: "Login necessário" });
}

/**
 * Middleware genérico (alias)
 * Pode ser usado para compatibilidade com código antigo que chamava "requireLogin"
 */
export const requireLogin = requireLoginAPI;
