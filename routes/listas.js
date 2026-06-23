const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");

const STATUS_VALIDOS = ["quero_ver", "ja_vi", "abandonei"];

function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token nao fornecido." });
  }
  const SECRET = process.env.JWT_SECRET || "fallback_secret";
  try {
    req.usuario = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: "Token invalido ou expirado." });
  }
}

// GET /listas — retorna todos os itens do usuário, agrupados por status
router.get("/", autenticar, async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = req.usuario.id;

    const result = await pool.query(
      "SELECT titulo_id, tipo, status, atualizado_em FROM listas_usuario WHERE usuario_id = $1 ORDER BY atualizado_em DESC",
      [userId]
    );

    const agrupado = { quero_ver: [], ja_vi: [], abandonei: [] };
    result.rows.forEach(item => {
      if (agrupado[item.status]) agrupado[item.status].push(item);
    });

    res.json(agrupado);
  } catch (e) {
    console.error("ERRO /listas GET:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// GET /listas/:tituloId — retorna o status atual de um título específico
router.get("/:tituloId", autenticar, async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = req.usuario.id;

    const result = await pool.query(
      "SELECT status FROM listas_usuario WHERE usuario_id = $1 AND titulo_id = $2",
      [userId, req.params.tituloId]
    );

    res.json({ status: result.rows[0]?.status || null });
  } catch (e) {
    console.error("ERRO /listas/:tituloId GET:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// PUT /listas/:tituloId — define ou atualiza o status
router.put("/:tituloId", autenticar, async (req, res) => {
  const { status, tipo } = req.body;
  const userId = req.usuario.id;
  const tituloId = req.params.tituloId;

  if (!STATUS_VALIDOS.includes(status)) {
    return res.status(400).json({ erro: "Status inválido." });
  }
  if (!tipo) {
    return res.status(400).json({ erro: "Tipo obrigatório." });
  }

  try {
    const { pool } = req.app.locals;
    const result = await pool.query(
      `INSERT INTO listas_usuario (usuario_id, titulo_id, tipo, status, atualizado_em)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (usuario_id, titulo_id)
       DO UPDATE SET status = $4, tipo = $3, atualizado_em = NOW()
       RETURNING titulo_id, tipo, status`,
      [userId, tituloId, tipo, status]
    );

    res.json({ item: result.rows[0] });
  } catch (e) {
    console.error("ERRO /listas/:tituloId PUT:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// DELETE /listas/:tituloId — remove da lista
router.delete("/:tituloId", autenticar, async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = req.usuario.id;

    const result = await pool.query(
      "DELETE FROM listas_usuario WHERE usuario_id = $1 AND titulo_id = $2 RETURNING id",
      [userId, req.params.tituloId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Item não encontrado na lista." });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("ERRO /listas/:tituloId DELETE:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

module.exports = router;