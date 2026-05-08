const { Pool } = require("pg");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

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
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || "https://lustv-ratings.up.railway.app";

app.use(cors());
app.use(express.json());

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

// ── Envio de email via Resend ──────────────────────────────────
async function enviarEmail({ to, subject, html }) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "LusTV-Ratings <onboarding@resend.dev>",
      to,
      subject,
      html,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || "Erro ao enviar email.");
  }
  return res.json();
}

const tendenciasRouter = require("./routes/tendencias");
const perfilRouter = require("./routes/perfil");
const socialRouter = require("./routes/social");

app.use("/tendencias", tendenciasRouter);
app.use("/perfil", perfilRouter);
app.use("/social", socialRouter);

app.get("/", (req, res) => res.json({ status: "LusTV backend rodando OK" }));

app.get("/ping", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ db: "conectado" });
  } catch (e) {
    res.status(500).json({ db: "erro", detalhe: e.message });
  }
});

// ── Cadastro ───────────────────────────────────────────────────
app.post("/auth/cadastrar", async (req, res) => {
  const { nome, senha, email } = req.body;
  if (!nome || !senha) return res.status(400).json({ erro: "Nome e senha obrigatorios." });
  if (nome.trim().length < 2) return res.status(400).json({ erro: "Nome muito curto." });
  if (senha.length < 3) return res.status(400).json({ erro: "Senha muito curta." });
  if (!email || !email.includes("@")) return res.status(400).json({ erro: "Email invalido." });

  try {
    // Verifica nome duplicado
    const nomeExiste = await pool.query("SELECT id FROM usuarios WHERE nome = $1", [nome.trim()]);
    if (nomeExiste.rows.length > 0) return res.status(409).json({ erro: "Nome de usuario ja em uso." });

    // Verifica email duplicado
    const emailExiste = await pool.query("SELECT id FROM usuarios WHERE email = $1", [email.trim().toLowerCase()]);
    if (emailExiste.rows.length > 0) return res.status(409).json({ erro: "Email ja cadastrado." });

    const hash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      "INSERT INTO usuarios (nome, senha, email) VALUES ($1, $2, $3) RETURNING id, nome, email",
      [nome.trim(), hash, email.trim().toLowerCase()]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, nome: user.nome }, SECRET, { expiresIn: "30d" });
    res.status(201).json({ token, usuario: { id: user.id, nome: user.nome, email: user.email } });
  } catch (e) {
    console.error("ERRO CADASTRO:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// ── Login ──────────────────────────────────────────────────────
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
    res.json({ token, usuario: { id: user.id, nome: user.nome, email: user.email } });
  } catch (e) {
    console.error("ERRO LOGIN:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// ── Esqueci a senha ────────────────────────────────────────────
app.post("/auth/esqueci-senha", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ erro: "Email obrigatorio." });

  try {
    const result = await pool.query("SELECT id, nome FROM usuarios WHERE email = $1", [email.trim().toLowerCase()]);

    // Responde sempre ok para não revelar se email existe
    if (result.rows.length === 0) return res.json({ ok: true });

    const user  = result.rows[0];
    const token = crypto.randomBytes(32).toString("hex");
    const exp   = new Date(Date.now() + 1000 * 60 * 60); // 1 hora

    await pool.query(
      "UPDATE usuarios SET reset_token = $1, reset_token_exp = $2 WHERE id = $3",
      [token, exp, user.id]
    );

    const link = `${FRONTEND_URL}/reset.html?token=${token}`;

    await enviarEmail({
      to: email.trim().toLowerCase(),
      subject: "Redefinição de senha — LusTV-Ratings",
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#111;color:#fff;padding:32px;border-radius:12px">
          <h2 style="color:#e50914;margin-bottom:8px">LusTV-Ratings</h2>
          <p>Olá, <strong>${user.nome}</strong>!</p>
          <p>Recebemos uma solicitação para redefinir sua senha. Clique no botão abaixo:</p>
          <a href="${link}" style="display:inline-block;margin:20px 0;background:#e50914;color:#fff;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:600">
            Redefinir senha
          </a>
          <p style="color:#888;font-size:13px">Este link expira em 1 hora. Se você não solicitou, ignore este email.</p>
        </div>
      `,
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("ERRO ESQUECI SENHA:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// ── Redefinir senha ────────────────────────────────────────────
app.post("/auth/redefinir-senha", async (req, res) => {
  const { token, novaSenha } = req.body;
  if (!token || !novaSenha) return res.status(400).json({ erro: "Token e nova senha obrigatorios." });
  if (novaSenha.length < 3) return res.status(400).json({ erro: "Senha muito curta." });

  try {
    const result = await pool.query(
      "SELECT id FROM usuarios WHERE reset_token = $1 AND reset_token_exp > NOW()",
      [token]
    );
    if (result.rows.length === 0) return res.status(400).json({ erro: "Token invalido ou expirado." });

    const hash = await bcrypt.hash(novaSenha, 10);
    await pool.query(
      "UPDATE usuarios SET senha = $1, reset_token = NULL, reset_token_exp = NULL WHERE id = $2",
      [hash, result.rows[0].id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("ERRO REDEFINIR SENHA:", e.message);
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

app.get("/avaliacoes/:filmeId/minha", autenticar, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, estrelas, comentario FROM avaliacoes WHERE filme_id=$1 AND usuario_id=$2",
      [req.params.filmeId, req.usuario.id]
    );
    res.json({ avaliacao: result.rows[0] || null });
  } catch (e) {
    console.error("ERRO MINHA AVALIACAO:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

app.put("/avaliacoes/:filmeId", autenticar, async (req, res) => {
  const { estrelas, comentario } = req.body;
  if (!estrelas || estrelas < 1 || estrelas > 5) return res.status(400).json({ erro: "Nota invalida." });
  try {
    const result = await pool.query(
      "UPDATE avaliacoes SET estrelas=$1, comentario=$2 WHERE filme_id=$3 AND usuario_id=$4 RETURNING id, estrelas, comentario",
      [estrelas, comentario || "", req.params.filmeId, req.usuario.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: "Avaliacao nao encontrada." });
    res.json({ avaliacao: result.rows[0] });
  } catch (e) {
    console.error("ERRO EDITAR AVALIACAO:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

app.listen(PORT, () => console.log("Servidor rodando na porta", PORT));

// v5
