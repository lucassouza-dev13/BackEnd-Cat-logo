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
const FRONTEND_URL = process.env.FRONTEND_URL || "https://lustv.netlify.app";

app.use(cors({
  origin: ['https://lustv.netlify.app', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
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
  const data = await res.json();
  console.log("RESEND RESPONSE:", JSON.stringify(data));
  if (!res.ok) {
    throw new Error(data.message || "Erro ao enviar email.");
  }
  return data;
}

// ── Cadastro ───────────────────────────────────────────────────
app.post("/auth/cadastrar", async (req, res) => {
  const { nome, senha, email } = req.body;
  if (!nome || !senha) return res.status(400).json({ erro: "Nome e senha obrigatorios." });
  if (nome.trim().length < 2) return res.status(400).json({ erro: "Nome muito curto." });
  if (senha.length < 3) return res.status(400).json({ erro: "Senha muito curta." });
  if (!email || !email.includes("@")) return res.status(400).json({ erro: "Email invalido." });

  try {
    const nomeExiste = await pool.query("SELECT id FROM usuarios WHERE nome = $1", [nome.trim()]);
    if (nomeExiste.rows.length > 0) return res.status(409).json({ erro: "Nome de usuario ja em uso." });

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
  console.log("ESQUECI SENHA chamado:", req.body);
  const { email } = req.body;
  if (!email) return res.status(400).json({ erro: "Email obrigatorio." });

  try {
    const result = await pool.query("SELECT id, nome FROM usuarios WHERE email = $1", [email.trim().toLowerCase()]);

    if (result.rows.length === 0) return res.json({ ok: true });

    const user  = result.rows[0];
    const token = crypto.randomBytes(32).toString("hex");
    const exp   = new Date(Date.now() + 1000 * 60 * 60);

    await pool.query(
      "UPDATE usuarios SET reset_token = $1, reset_token_exp = $2 WHERE id = $3",
      [token, exp, user.id]
    );

    const link = `${FRONTEND_URL}/reset.html?token=${token}`;

    await enviarEmail({
      to: email.trim().toLowerCase(),
      subject: "Redefinição de senha — LusTV-Ratings",
      html: `
<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0d0d0d;font-family:'Inter',Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0d0d;padding:40px 16px">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#111111;border:1px solid #1e1e1e;border-radius:16px;overflow:hidden">

          <!-- Header com logo -->
          <tr>
            <td style="padding:28px 32px 20px">
              <table cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding-right:10px;vertical-align:middle">
                    <div style="width:32px;height:32px;background:#2d1b6e;border-radius:7px;display:inline-block;text-align:center;line-height:32px;font-family:Georgia,serif;font-size:22px;font-weight:700;color:#9b6fd4">L</div>
                  </td>
                  <td style="vertical-align:middle">
                    <span style="font-size:18px;font-weight:600;color:#9b6fd4;letter-spacing:1px">LUSTV</span>
                  </td>
                </tr>
              </table>
              <p style="margin:8px 0 0;font-size:11px;color:#444;letter-spacing:2px;text-transform:uppercase">Avalie. Descubra. Compartilhe.</p>
            </td>
          </tr>

          <!-- Linha roxa decorativa -->
          <tr>
            <td style="padding:0 32px">
              <div style="border-left:3px solid #9b6fd4;padding-left:14px">
                <p style="margin:0;font-size:22px;font-weight:600;color:#ffffff;line-height:1.2">Redefinir senha</p>
                <p style="margin:4px 0 0;font-size:13px;color:#555">Recebemos sua solicitação</p>
              </div>
            </td>
          </tr>

          <!-- Corpo -->
          <tr>
            <td style="padding:24px 32px">
              <p style="margin:0 0 8px;font-size:15px;color:#cccccc">
                Olá, <strong style="color:#ffffff">${user.nome}</strong>!
              </p>
              <p style="margin:0 0 28px;font-size:14px;color:#888888;line-height:1.6">
                Recebemos uma solicitação para redefinir a senha da sua conta. Clique no botão abaixo para continuar:
              </p>

              <!-- Botão -->
              <table cellpadding="0" cellspacing="0">
                <tr>
                  <td style="border-radius:8px;background:#9b6fd4">
                    <a href="${link}" style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px">
                      → Redefinir senha
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Divider -->
          <tr>
            <td style="padding:0 32px">
              <div style="height:1px;background:#1e1e1e"></div>
            </td>
          </tr>

          <!-- Rodapé -->
          <tr>
            <td style="padding:20px 32px 28px">
              <p style="margin:0;font-size:12px;color:#444444;line-height:1.6">
                Este link expira em <strong style="color:#555">1 hora</strong>. Se você não solicitou a redefinição, pode ignorar este email com segurança.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
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

const tendenciasRoutes = require("./routes/tendencias");
const perfilRoutes = require("./routes/perfil");
const socialRoutes = require("./routes/social");

app.use("/tendencias", tendenciasRoutes);
app.use("/perfil", perfilRoutes);
app.use("/social", socialRoutes);

app.listen(PORT, () => console.log("Servidor rodando na porta", PORT));

// v6
