const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");

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
router.get("/", autenticar, async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = req.usuario.id;

    const userResult = await pool.query(
      "SELECT id, nome, avatar, criado_em FROM usuarios WHERE id = $1",
      [userId]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }
    const usuario = userResult.rows[0];

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

    const recentesResult = await pool.query(
      `SELECT id, filme_id, tipo, estrelas, comentario, criado_em
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

// GET /perfil/:id (perfil público)
router.get("/:id", async (req, res) => {
  try {
    const { pool } = req.app.locals;
    const userId = parseInt(req.params.id);

    const userResult = await pool.query(
      "SELECT id, nome, avatar, criado_em FROM usuarios WHERE id = $1",
      [userId]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }
    const usuario = userResult.rows[0];

    const statsResult = await pool.query(
      `SELECT
        COUNT(*) AS total_avaliacoes,
        ROUND(AVG(estrelas)::numeric, 1) AS media_estrelas,
        COUNT(CASE WHEN estrelas = 5 THEN 1 END) AS notas_5
      FROM avaliacoes
      WHERE usuario_id = $1`,
      [userId]
    );

    const recentesResult = await pool.query(
      `SELECT id, filme_id, estrelas, comentario, criado_em
       FROM avaliacoes
       WHERE usuario_id = $1
       ORDER BY criado_em DESC
       LIMIT 10`,
      [userId]
    );

    const seguidoresResult = await pool.query(
      "SELECT COUNT(*) AS total FROM follows WHERE following_id = $1",
      [userId]
    );

    const seguindoResult = await pool.query(
      "SELECT COUNT(*) AS total FROM follows WHERE follower_id = $1",
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
        total_avaliacoes: parseInt(statsResult.rows[0].total_avaliacoes) || 0,
        media_estrelas: parseFloat(statsResult.rows[0].media_estrelas) || 0,
        notas_5: parseInt(statsResult.rows[0].notas_5) || 0,
        seguidores: parseInt(seguidoresResult.rows[0].total) || 0,
        seguindo: parseInt(seguindoResult.rows[0].total) || 0,
      },
      recentes: recentesResult.rows,
    });
  } catch (e) {
    console.error("ERRO /perfil/:id GET:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// PUT /perfil
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

    if (nome) {
      const existe = await pool.query(
        "SELECT id FROM usuarios WHERE nome = $1 AND id != $2",
        [nome.trim(), userId]
      );
      if (existe.rows.length > 0) {
        return res.status(409).json({ erro: "Nome já em uso." });
      }
    }

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

// POST /perfil/conquistas/verificar
router.post("/conquistas/verificar", autenticar, async (req, res) => {
  const { pool } = req.app.locals;
  const userId = req.usuario.id;

  try {
    // Busca estatísticas do usuário
    const statsRes = await pool.query(
      `SELECT
        COUNT(*) AS total,
        COUNT(CASE WHEN tipo = 'game' THEN 1 END) AS jogos,
        COUNT(CASE WHEN tipo = 'tv'   THEN 1 END) AS series
       FROM avaliacoes WHERE usuario_id = $1`,
      [userId]
    );
    const s = statsRes.rows[0];
    const total  = parseInt(s.total);
    const jogos  = parseInt(s.jogos);
    const series = parseInt(s.series);

    // Definição das conquistas
    const CONQUISTAS = [
      { id: 'estreante',    emoji: '🎬', nome: 'Estreante',    desc: 'Fez sua primeira avaliação',         cond: total  >= 1   },
      { id: 'cinefilo',     emoji: '🍿', nome: 'Cinéfilo',     desc: '10 avaliações feitas',               cond: total  >= 10  },
      { id: 'critico',      emoji: '🎭', nome: 'Crítico',      desc: '25 avaliações feitas',               cond: total  >= 25  },
      { id: 'mestre',       emoji: '🏆', nome: 'Mestre',       desc: '50 avaliações feitas',               cond: total  >= 50  },
      { id: 'lendario',     emoji: '👑', nome: 'Lendário',     desc: '100 avaliações feitas',              cond: total  >= 100 },
      { id: 'gamer',        emoji: '🎮', nome: 'Gamer',        desc: '5 jogos avaliados',                  cond: jogos  >= 5   },
      { id: 'maratonista',  emoji: '📺', nome: 'Maratonista',  desc: '5 séries avaliadas',                 cond: series >= 5   },
    ];

    // Busca conquistas já desbloqueadas
    const jaRes = await pool.query(
      "SELECT conquista_id FROM conquistas_usuarios WHERE usuario_id = $1",
      [userId]
    );
    const jaDesbloqueadas = new Set(jaRes.rows.map(r => r.conquista_id));

    // Filtra as novas
    const novas = CONQUISTAS.filter(c => c.cond && !jaDesbloqueadas.has(c.id));

    // Salva as novas no banco
    for (const c of novas) {
      await pool.query(
        "INSERT INTO conquistas_usuarios (usuario_id, conquista_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        [userId, c.id]
      );
    }

    // Retorna todas desbloqueadas + quais são novas
    const todasRes = await pool.query(
      "SELECT conquista_id, desbloqueada_em FROM conquistas_usuarios WHERE usuario_id = $1 ORDER BY desbloqueada_em ASC",
      [userId]
    );

    res.json({
      novas:  novas,
      todas:  todasRes.rows,
    });
  } catch (e) {
    console.error("ERRO CONQUISTAS:", e.message);
    res.status(500).json({ erro: e.message });
  }
});

module.exports = router;
