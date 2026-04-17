require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const db      = require("./db");

const app    = express();
const PORT   = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET;

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(cors());          // permite que o frontend chame este backend
app.use(express.json());  // lê JSON no body das requisições

// ─── Middleware: verificar token JWT ──────────────────────────────────────────
function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token não fornecido." });
  }
  try {
    req.usuario = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: "Token inválido ou expirado." });
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// ROTAS DE AUTENTICAÇÃO
// ══════════════════════════════════════════════════════════════════════════════

// POST /auth/cadastrar  ─  cria conta nova
app.post("/auth/cadastrar", async (req, res) => {
  const { nome, senha } = req.body;

  if (!nome || !senha)          return res.status(400).json({ erro: "Nome e senha são obrigatórios." });
  if (nome.trim().length < 2)   return res.status(400).json({ erro: "Nome muito curto (mínimo 2 caracteres)." });
  if (senha.length < 3)         return res.status(400).json({ erro: "Senha muito curta (mínimo 3 caracteres)." });

  try {
    // verifica se já existe
    const existe = await db.query("SELECT id FROM usuarios WHERE nome = $1", [nome.trim()]);
    if (existe.rows.length > 0) return res.status(409).json({ erro: "Este nome de usuário já está em uso." });

    const hash = await bcrypt.hash(senha, 10);
    const result = await db.query(
      "INSERT INTO usuarios (nome, senha) VALUES ($1, $2) RETURNING id, nome",
      [nome.trim(), hash]
    );

    const user  = result.rows[0];
    const token = jwt.sign({ id: user.id, nome: user.nome }, SECRET, { expiresIn: "30d" });

    res.status(201).json({ token, usuario: { id: user.id, nome: user.nome } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: "Erro interno no servidor." });
  }
});

// POST /auth/entrar  ─  login com conta existente
app.post("/auth/entrar", async (req, res) => {
  const { nome, senha } = req.body;

  if (!nome || !senha) return res.status(400).json({ erro: "Nome e senha são obrigatórios." });

  try {
    const result = await db.query("SELECT * FROM usuarios WHERE nome = $1", [nome.trim()]);
    if (result.rows.length === 0) return res.status(404).json({ erro: "Usuário não encontrado." });

    const user = result.rows[0];
    const ok   = await bcrypt.compare(senha, user.senha);
    if (!ok) return res.status(401).json({ erro: "Senha incorreta." });

    const token = jwt.sign({ id: user.id, nome: user.nome }, SECRET, { expiresIn: "30d" });
    res.json({ token, usuario: { id: user.id, nome: user.nome } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: "Erro interno no servidor." });
  }
});

// GET /auth/me  ─  retorna dados do usuário logado (valida token)
app.get("/auth/me", autenticar, (req, res) => {
  res.json({ usuario: req.usuario });
});

// ══════════════════════════════════════════════════════════════════════════════
// ROTAS DE AVALIAÇÕES
// ══════════════════════════════════════════════════════════════════════════════

// GET /avaliacoes/:filmeId  ─  lista avaliações de um filme
app.get("/avaliacoes/:filmeId", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        av.id,
        av.estrelas,
        av.comentario,
        av.criado_em,
        u.nome AS autor,
        u.id   AS autor_id
      FROM avaliacoes av
      JOIN usuarios u ON u.id = av.usuario_id
      WHERE av.filme_id = $1
      ORDER BY av.criado_em DESC
    `, [req.params.filmeId]);

    res.json({ avaliacoes: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: "Erro ao buscar avaliações." });
  }
});

// POST /avaliacoes/:filmeId  ─  envia nova avaliação (requer login)
app.post("/avaliacoes/:filmeId", autenticar, async (req, res) => {
  const { estrelas, comentario } = req.body;

  if (!estrelas || estrelas < 1 || estrelas > 5) {
    return res.status(400).json({ erro: "Nota inválida (deve ser entre 1 e 5)." });
  }

  try {
    const result = await db.query(`
      INSERT INTO avaliacoes (filme_id, usuario_id, estrelas, comentario)
      VALUES ($1, $2, $3, $4)
      RETURNING id, estrelas, comentario, criado_em
    `, [req.params.filmeId, req.usuario.id, estrelas, comentario || ""]);

    res.status(201).json({ avaliacao: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") { // unique_violation - usuário já avaliou
      return res.status(409).json({ erro: "Você já avaliou este título." });
    }
    console.error(e);
    res.status(500).json({ erro: "Erro ao salvar avaliação." });
  }
});

// DELETE /avaliacoes/:avaliacaoId  ─  remove avaliação própria
app.delete("/avaliacoes/:avaliacaoId", autenticar, async (req, res) => {
  try {
    const result = await db.query(
      "DELETE FROM avaliacoes WHERE id = $1 AND usuario_id = $2 RETURNING id",
      [req.params.avaliacaoId, req.usuario.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: "Avaliação não encontrada ou sem permissão." });
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: "Erro ao remover avaliação." });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "LusTV backend rodando ✅" }));

// ─── Iniciar servidor ─────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));

app.get("/teste", (req, res) => {
  res.send("ok");
});