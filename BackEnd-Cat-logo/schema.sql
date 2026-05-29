-- Tabela de usuários
CREATE TABLE IF NOT EXISTS usuarios (
  id        SERIAL PRIMARY KEY,
  nome      TEXT UNIQUE NOT NULL,
  senha     TEXT NOT NULL,           -- senha armazenada como hash bcrypt
  avatar    TEXT DEFAULT NULL,       -- emoji ou URL do avatar do usuário
  criado_em TIMESTAMPTZ DEFAULT NOW()
);

-- Tabela de avaliações
CREATE TABLE IF NOT EXISTS avaliacoes (
  id         SERIAL PRIMARY KEY,
  filme_id   TEXT NOT NULL,          -- ID do filme/série na API do TMDB
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  estrelas   INTEGER NOT NULL CHECK (estrelas BETWEEN 1 AND 5),
  comentario TEXT DEFAULT '',
  criado_em  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (filme_id, usuario_id)      -- cada usuário avalia um filme apenas 1 vez
);

-- Índices para buscas rápidas
CREATE INDEX IF NOT EXISTS idx_avaliacoes_filme    ON avaliacoes(filme_id);
CREATE INDEX IF NOT EXISTS idx_avaliacoes_usuario  ON avaliacoes(usuario_id);
CREATE INDEX IF NOT EXISTS idx_avaliacoes_criado_em ON avaliacoes(criado_em DESC);
