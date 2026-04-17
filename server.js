require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const db      = require("./db");

console.log("SERVER INICIOU");
console.log("DB IMPORTADO:", !!db);
console.log("DB TYPE:", typeof db);

const app    = express();
const PORT   = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET;

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─── Middleware: autenticação ──────────────────────────────────────────────────
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
// ROTAS
// ══════════════════════════════════════════════════════════════════════════════

// CADASTRO
app.post("/auth/cadastrar", async (req, res) => {
  const { nome, senha } = req.body;

  if (!nome || !senha)
    return res.status(400).json({ erro: "Nome e senha são obrigatórios." });

  try {
    const existe = await db.query(
      "SELECT id FROM usuarios WHERE nome = $1",
      [nome.trim()]
    );

    if (existe.rows.length > 0)
      return res.status(409).json({ erro: "Usuário já existe." });

    const hash = await bcrypt.hash(senha, 10);

    const result = await db.query(
      "INSERT INTO usuarios (nome, senha) VALUES ($1, $2) RETURNING id, nome",
      [nome.trim(), hash]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { id: user.id, nome: user.nome },
      SECRET,
      { expiresIn: "30d" }
    );

    res.status(201).json({ token, usuario: user });

  } catch (e) {
    console.error("ERRO CADASTRO:", e);
    res.status(500).json({ erro: "Erro interno no servidor." });
  }
});

// LOGIN
app.post("/auth/entrar", async (req, res) => {
  const { nome, senha } = req.body;

  if (!nome || !senha)
    return res.status(400).json({ erro: "Nome e senha são obrigatórios." });

  try {
    const result = await db.query(
      "SELECT * FROM usuarios WHERE nome = $1",
      [nome.trim()]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ erro: "Usuário não encontrado." });

    const user = result.rows[0];

    const ok = await bcrypt.compare(senha, user.senha);
    if (!ok)
      return res.status(401).json({ erro: "Senha incorreta." });

    const token = jwt.sign(
      { id: user.id, nome: user.nome },
      SECRET,
      { expiresIn: "30d" }
    );

    res.json({ token, usuario: { id: user.id, nome: user.nome } });

  } catch (e) {
    console.error("ERRO LOGIN:", e);
    res.status(500).json({ erro: "Erro interno no servidor." });
  }
});

// ME
app.get("/auth/me", autenticar, (req, res) => {
  res.json({ usuario: req.usuario });
});

// AVALIAÇÕES
app.get("/avaliacoes/:filmeId", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT av.id, av.estrelas, av.comentario, av.criado_em,
             u.nome AS autor, u.id AS autor_id
      FROM avaliacoes av
      JOIN usuarios u ON u.id = av.usuario_id
      WHERE av.filme_id = $1
      ORDER BY av.criado_em DESC
    `, [req.params.filmeId]);

    res.json({ avaliacoes: result.rows });

  } catch (e) {
    console.error("ERRO AVALIAÇÕES:", e);
    res.status(500).json({ erro: "Erro ao buscar avaliações." });
  }
});

// CREATE AVALIAÇÃO
app.post("/avaliacoes/:filmeId", autenticar, async (req, res) => {
  const { estrelas, comentario } = req.body;

  if (!estrelas || estrelas < 1 || estrelas > 5) {
    return res.status(400).json({ erro: "Nota inválida." });
  }

  try {
    const result = await db.query(`
      INSERT INTO avaliacoes (filme_id, usuario_id, estrelas, comentario)
      VALUES ($1, $2, $3, $4)
      RETURNING id, estrelas, comentario, criado_em
    `, [req.params.filmeId, req.usuario.id, estrelas, comentario || ""]);

    res.status(201).json({ avaliacao: result.rows[0] });

  } catch (e) {
    console.error("ERRO AVALIAR:", e);
    res.status(500).json({ erro: "Erro ao salvar avaliação." });
  }
});

// DELETE
app.delete("/avaliacoes/:avaliacaoId", autenticar, async (req, res) => {
  try {
    const result = await db.query(
      "DELETE FROM avaliacoes WHERE id=$1 AND usuario_id=$2 RETURNING id",
      [req.params.avaliacaoId, req.usuario.id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ erro: "Não encontrado." });

    res.json({ ok: true });

  } catch (e) {
    console.error("ERRO DELETE:", e);
    res.status(500).json({ erro: "Erro ao remover." });
  }
});

// TESTE
app.get("/", (req, res) => {
  res.json({ status: "LusTV backend rodando " });
});

app.get("/teste", (req, res) => {
  res.send("ok");
});

// START
app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});