const express = require("express");
const router  = express.Router();
const jwt     = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET || "fallback_secret";

function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ erro: "Token nao fornecido." });
  try {
    req.usuario = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: "Token invalido ou expirado." });
  }
}

// Seguir usuário
router.post("/follow", autenticar, async (req, res) => {
  const pool = req.app.locals.pool;
  const { following_id } = req.body;
  const follower_id = req.usuario.id;

  if (!following_id) return res.status(400).json({ erro: "following_id obrigatorio." });
  if (follower_id === following_id) return res.status(400).json({ erro: "Voce nao pode seguir a si mesmo." });

  try {
    const result = await pool.query(
      "INSERT INTO follows (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING *",
      [follower_id, following_id]
    );

    // Só notifica se realmente inseriu (não era seguidor ainda)
    if (result.rows.length > 0) {
      await pool.query(
        "INSERT INTO notificacoes (usuario_id, ator_id, tipo) VALUES ($1, $2, 'novo_seguidor')",
        [following_id, follower_id]
      );
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Deixar de seguir
router.delete("/follow", autenticar, async (req, res) => {
  const pool = req.app.locals.pool;
  const { following_id } = req.body;
  const follower_id = req.usuario.id;

  try {
    await pool.query(
      "DELETE FROM follows WHERE follower_id=$1 AND following_id=$2",
      [follower_id, following_id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Checar se segue
router.get("/follow/check/:following_id", autenticar, async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const result = await pool.query(
      "SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2",
      [req.usuario.id, req.params.following_id]
    );
    res.json({ seguindo: result.rows.length > 0 });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Feed: avaliações recentes de quem o usuário segue
router.get("/feed", autenticar, async (req, res) => {
  const pool   = req.app.locals.pool;
  const limit  = Math.min(parseInt(req.query.limit)  || 20, 50);
  const offset = parseInt(req.query.offset) || 0;

  try {
    const result = await pool.query(
      `SELECT
         av.id          AS avaliacao_id,
         av.filme_id,
         av.estrelas,
         av.comentario,
         av.criado_em,
         u.id           AS usuario_id,
         u.nome         AS usuario_nome
       FROM follows f
       JOIN avaliacoes av ON av.usuario_id = f.following_id
       JOIN usuarios   u  ON u.id          = av.usuario_id
       WHERE f.follower_id = $1
       ORDER BY av.criado_em DESC
       LIMIT $2 OFFSET $3`,
      [req.usuario.id, limit, offset]
    );

    const countRes = await pool.query(
      `SELECT COUNT(*) FROM follows f
       JOIN avaliacoes av ON av.usuario_id = f.following_id
       WHERE f.follower_id = $1`,
      [req.usuario.id]
    );

    res.json({
      feed:   result.rows,
      total:  parseInt(countRes.rows[0].count),
      limit,
      offset,
    });
  } catch (e) {
    console.error("ERRO FEED:", e.message);
    res.status(500).json({ erro: e.message });
  }
});

// Buscar usuários por nome
router.get("/usuarios/buscar", autenticar, async (req, res) => {
  const pool = req.app.locals.pool;
  const { q } = req.query;

  if (!q || q.trim().length < 2)
    return res.status(400).json({ erro: "Query muito curta." });

  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.nome,
         COUNT(DISTINCT av.id)           AS total_avaliacoes,
         COUNT(DISTINCT f2.follower_id)  AS total_seguidores,
         EXISTS (
           SELECT 1 FROM follows f3
           WHERE f3.follower_id = $2 AND f3.following_id = u.id
         ) AS ja_sigo
       FROM usuarios u
       LEFT JOIN avaliacoes av ON av.usuario_id = u.id
       LEFT JOIN follows    f2 ON f2.following_id = u.id
       WHERE u.nome ILIKE $1 AND u.id != $2
       GROUP BY u.id
       ORDER BY total_avaliacoes DESC
       LIMIT 20`,
      [`%${q.trim()}%`, req.usuario.id]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Buscar notificações do usuário logado
router.get("/notificacoes", autenticar, async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const result = await pool.query(
      `SELECT
         n.id,
         n.tipo,
         n.lida,
         n.criado_em,
         u.id     AS ator_id,
         u.nome   AS ator_nome,
         u.avatar AS ator_avatar
       FROM notificacoes n
       JOIN usuarios u ON u.id = n.ator_id
       WHERE n.usuario_id = $1
       ORDER BY n.criado_em DESC
       LIMIT 20`,
      [req.usuario.id]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Marcar todas as notificações como lidas
router.patch("/notificacoes/lidas", autenticar, async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    await pool.query(
      "UPDATE notificacoes SET lida = TRUE WHERE usuario_id = $1",
      [req.usuario.id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

module.exports = router;
