const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");

// Middleware de autenticação (importado do server.js via app.locals)
function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token nao fornecido." });
  }
  const jwt = require("jsonwebtoken");
  const SECRET = process.env.JWT_SECRET || "fallback_secret";
  try {
    req.usuario = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: "Token invalido ou expirado." });
  }
}

// GET /perfil
// Retorna dados completos do perfil + estatísticas
router.get("/", autenticar, async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = req.usuario.id;

    // Dados do usuário
    const userResult = await pool.query(
      "SELECT id, nome, avatar, criado_em FROM usuarios WHERE id = $1",
      [userId]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }
    const usuario = userResult.rows[0];

    // Estatísticas de avaliações
    const statsResult = await pool.query(
      `SELECT
        COUNT(*) AS total_avaliacoes,
        ROUND(AVG(estrelas)::numeric, 1) AS media_estrelas,
        COUNT(CASE WHEN estrelas = 5 THEN 1 END) AS notas_5,
        COUNT(CASE WHEN estrelas >= 4 THEN 1 END) AS notas_altas
      FROM avaliacoes
      WHERE usuario_id = $1`,
      [userId]
    );
    const stats = statsResult.rows[0];

    // Filmes avaliados recentemente
    const recentesResult = await pool.query(
      `SELECT filme_id, estrelas, comentario, criado_em
       FROM avaliacoes
       WHERE usuario_id = $1
       ORDER BY criado_em DESC
       LIMIT 5`,
      [userId]
    );

    res.json({
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        avatar: usuario.avatar || null,
        membro_desde: usuario.criado_em,
      },
      estatisticas: {
        total_avaliacoes: parseInt(stats.total_avaliacoes) || 0,
        media_estrelas: parseFloat(stats.media_estrelas) || 0,
        notas_5: parseInt(stats.notas_5) || 0,
        notas_altas: parseInt(stats.notas_altas) || 0,
      },
      recentes: recentesResult.rows,
    });
  } catch (e) {
    console.error("ERRO /perfil GET:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// PUT /perfil
// Atualiza nome e/ou avatar do usuário
router.put("/", autenticar, async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = req.usuario.id;
    const { nome, avatar } = req.body;

    if (!nome && !avatar) {
      return res.status(400).json({ erro: "Nada para atualizar." });
    }

    if (nome && nome.trim().length < 2) {
      return res.status(400).json({ erro: "Nome muito curto." });
    }

    // Verifica se o novo nome já existe (se estiver trocando)
    if (nome) {
      const existe = await pool.query(
        "SELECT id FROM usuarios WHERE nome = $1 AND id != $2",
        [nome.trim(), userId]
      );
      if (existe.rows.length > 0) {
        return res.status(409).json({ erro: "Nome já em uso." });
      }
    }

    // Monta query dinamicamente
    const campos = [];
    const valores = [];
    let idx = 1;

    if (nome) { campos.push(`nome = $${idx++}`); valores.push(nome.trim()); }
    if (avatar) { campos.push(`avatar = $${idx++}`); valores.push(avatar); }
    valores.push(userId);

    const result = await pool.query(
      `UPDATE usuarios SET ${campos.join(", ")} WHERE id = $${idx} RETURNING id, nome, avatar`,
      valores
    );

    res.json({ usuario: result.rows[0] });
  } catch (e) {
    console.error("ERRO /perfil PUT:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// PUT /perfil/senha
// Troca a senha do usuário
router.put("/senha", autenticar, async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = req.usuario.id;
    const { senha_atual, senha_nova } = req.body;

    if (!senha_atual || !senha_nova) {
      return res.status(400).json({ erro: "Senha atual e nova são obrigatórias." });
    }
    if (senha_nova.length < 3) {
      return res.status(400).json({ erro: "Senha nova muito curta." });
    }

    const result = await pool.query("SELECT senha FROM usuarios WHERE id = $1", [userId]);
    const ok = await bcrypt.compare(senha_atual, result.rows[0].senha);
    if (!ok) return res.status(401).json({ erro: "Senha atual incorreta." });

    const hash = await bcrypt.hash(senha_nova, 10);
    await pool.query("UPDATE usuarios SET senha = $1 WHERE id = $2", [hash, userId]);

    res.json({ ok: true, mensagem: "Senha atualizada com sucesso." });
  } catch (e) {
    console.error("ERRO /perfil/senha:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

module.exports = router;
