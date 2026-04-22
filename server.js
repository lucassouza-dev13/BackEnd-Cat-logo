const { Pool } = require("pg");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const url = new URL(process.env.DATABASE_URL);

const pool = new Pool({
  host: url.hostname,
  port: url.port,
  user: url.username,
  password: url.password,
  database: url.pathname.slice(1),
  ssl: { rejectUnauthorized: false },
  family: 4,
});

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || "fallback_secret";

app.use(cors());
app.use(express.json());

// Disponibiliza o pool para as rotas modulares via app.locals
app.locals.pool = pool;

function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token nao fornecido." });
  }
  try {
    req.usuario = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: "Token invalido ou expirado." });
  }
}

// ─── Rotas modulares ──────────────────────────────────────────────────────────
const tendenciasRouter = require("./routes/tendencias");
const perfilRouter = require("./routes/perfil");

app.use("/tendencias", tendenciasRouter);
app.use("/perfil", perfilRouter);
// ─────────────────────────────────────────────────────────────────────────────

app.get("/", (req, res) => res.json({ status: "LusTV backend rodando OK" }));

app.get("/ping", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ db: "conectado" });
  } catch (e) {
    res.status(500).json({ db: "erro", detalhe: e.message });
  }
});

app.post("/auth/cadastrar", async (req, res) => {
  const { nome, senha } = req.body;
  if (!nome || !senha) return res.status(400).json({ erro: "Nome e senha obrigatorios." });
  if (nome.trim().length < 2) return res.status(400).json({ erro: "Nome muito curto." });
  if (senha.length < 3) return res.status(400).json({ erro: "Senha muito curta." });
  try {
    const existe = await pool.query("SELECT id FROM usuarios WHERE nome = $1", [nome.trim()]);
    if (existe.rows.length > 0) return res.status(409).json({ erro: "Nome de usuario ja em uso." });
    const hash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      "INSERT INTO usuarios (nome, senha) VALUES ($1, $2) RETURNING id, nome",
      [nome.trim(), hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, nome: user.nome }, SECRET, { expiresIn: "30d" });
    res.status(201).json({ token, usuario: { id: user.id, nome: user.nome } });
  } catch (e) {
    console.error("ERRO CADASTRO:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

app.post("/auth/entrar", async (req, res) => {
  const { nome, senha } = req.body;
  if (!nome || !senha) return res.status(400).json({ erro: "Nome e senha obrigatorios." });
  try {
    const result = await pool.query("SELECT * FROM usuarios WHERE nome = $1", [nome.trim()]);
    if (result.rows.length === 0) return res.status(404).json({ erro: "Usuario nao encontrado." });
    const user = result.rows[0];
    const ok = await bcrypt.compare(senha, user.senha);
    if (!ok) return res.status(401).json({ erro: "Senha incorreta." });
    const token = jwt.sign({ id: user.id, nome: user.nome }, SECRET, { expiresIn: "30d" });
    res.json({ token, usuario: { id: user.id, nome: user.nome } });
  } catch (e) {
    console.error("ERRO LOGIN:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

app.get("/auth/me", autenticar, (req, res) => res.json({ usuario: req.usuario }));

app.get("/avaliacoes/:filmeId", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT av.id, av.estrelas, av.comentario, av.criado_em, u.nome AS autor, u.id AS autor_id FROM avaliacoes av JOIN usuarios u ON u.id = av.usuario_id WHERE av.filme_id = $1 ORDER BY av.criado_em DESC",
      [req.params.filmeId]
    );
    res.json({ avaliacoes: result.rows });
  } catch (e) {
    console.error("ERRO AVALIACOES:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

app.post("/avaliacoes/:filmeId", autenticar, async (req, res) => {
  const { estrelas, comentario } = req.body;
  if (!estrelas || estrelas < 1 || estrelas > 5) return res.status(400).json({ erro: "Nota invalida." });
  try {
    const result = await pool.query(
      "INSERT INTO avaliacoes (filme_id, usuario_id, estrelas, comentario) VALUES ($1, $2, $3, $4) RETURNING id, estrelas, comentario, criado_em",
      [req.params.filmeId, req.usuario.id, estrelas, comentario || ""]
    );
    res.status(201).json({ avaliacao: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ erro: "Voce ja avaliou este titulo." });
    console.error("ERRO AVALIAR:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

app.delete("/avaliacoes/:avaliacaoId", autenticar, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM avaliacoes WHERE id=$1 AND usuario_id=$2 RETURNING id",
      [req.params.avaliacaoId, req.usuario.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: "Nao encontrado." });
    res.json({ ok: true });
  } catch (e) {
    console.error("ERRO DELETE:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

app.listen(PORT, () => console.log("Servidor rodando na porta", PORT));

// v3
