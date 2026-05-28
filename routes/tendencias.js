const express = require("express");
const router = express.Router();

const TMDB_KEY = process.env.TMDB_API_KEY;
const TMDB = "https://api.themoviedb.org/3";
const LANG = "pt-BR";

// Busca genérica na TMDB
async function tmdb(path, params = {}) {
  const url = new URL(`${TMDB}${path}`);
  url.searchParams.set("api_key", TMDB_KEY);
  url.searchParams.set("language", LANG);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const res = await fetch(url.toString());
  if (!res.ok) throw new Error(`TMDB erro ${res.status}: ${path}`);
  return res.json();
}

// GET /tendencias/semana
// Filmes mais avaliados no seu banco na última semana
router.get("/semana", async (req, res) => {
  try {
    const { pool } = req.app.locals;

    const result = await pool.query(`
      SELECT
        filme_id,
        COUNT(*) AS total_avaliacoes,
        ROUND(AVG(estrelas)::numeric, 1) AS media_estrelas
      FROM avaliacoes
      WHERE criado_em >= NOW() - INTERVAL '7 days'
      GROUP BY filme_id
      ORDER BY total_avaliacoes DESC, media_estrelas DESC
      LIMIT 10
    `);

    if (result.rows.length === 0) {
      return res.json({ filmes: [], fonte: "banco" });
    }

    // Busca detalhes de cada filme na TMDB
    const filmes = await Promise.all(
      result.rows.map(async (row) => {
        try {
          const tmdbData = await tmdb(`/movie/${row.filme_id}`);
          return {
            id: row.filme_id,
            titulo: tmdbData.title,
            titulo_original: tmdbData.original_title,
            poster: tmdbData.poster_path
              ? `https://image.tmdb.org/t/p/w200${tmdbData.poster_path}`
              : null,
            ano: tmdbData.release_date?.slice(0, 4) || null,
            generos: tmdbData.genres?.map((g) => g.name) || [],
            total_avaliacoes: parseInt(row.total_avaliacoes),
            media_estrelas: parseFloat(row.media_estrelas),
          };
        } catch {
          // Se TMDB falhar para um filme, retorna só os dados do banco
          return {
            id: row.filme_id,
            titulo: `Filme #${row.filme_id}`,
            poster: null,
            total_avaliacoes: parseInt(row.total_avaliacoes),
            media_estrelas: parseFloat(row.media_estrelas),
          };
        }
      })
    );

    res.json({ filmes, fonte: "banco+tmdb" });
  } catch (e) {
    console.error("ERRO /tendencias/semana:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// GET /tendencias/mundo?pagina=1
// Filmes trending globais via TMDB (semana)
router.get("/mundo", async (req, res) => {
  try {
    const pagina = parseInt(req.query.pagina) || 1;
    const data = await tmdb("/trending/movie/week", { page: pagina });

    const filmes = data.results.map((f) => ({
      id: f.id,
      titulo: f.title,
      titulo_original: f.original_title,
      poster: f.poster_path
        ? `https://image.tmdb.org/t/p/w200${f.poster_path}`
        : null,
      ano: f.release_date?.slice(0, 4) || null,
      nota_tmdb: f.vote_average?.toFixed(1),
      popularidade: Math.round(f.popularity),
      sinopse: f.overview,
    }));

    res.json({
      filmes,
      pagina: data.page,
      total_paginas: data.total_pages,
    });
  } catch (e) {
    console.error("ERRO /tendencias/mundo:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// GET /tendencias/generos
// Lista todos os gêneros disponíveis na TMDB
router.get("/generos", async (req, res) => {
  try {
    const data = await tmdb("/genre/movie/list");
    res.json({ generos: data.genres });
  } catch (e) {
    console.error("ERRO /tendencias/generos:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

// GET /tendencias/genero/:generoId?pagina=1
// Filmes populares de um gênero específico
router.get("/genero/:generoId", async (req, res) => {
  try {
    const { generoId } = req.params;
    const pagina = parseInt(req.query.pagina) || 1;

    const data = await tmdb("/discover/movie", {
      with_genres: generoId,
      sort_by: "popularity.desc",
      page: pagina,
    });

    const filmes = data.results.map((f) => ({
      id: f.id,
      titulo: f.title,
      poster: f.poster_path
        ? `https://image.tmdb.org/t/p/w200${f.poster_path}`
        : null,
      ano: f.release_date?.slice(0, 4) || null,
      nota_tmdb: f.vote_average?.toFixed(1),
      sinopse: f.overview,
    }));

    res.json({
      filmes,
      genero_id: generoId,
      pagina: data.page,
      total_paginas: data.total_pages,
    });
  } catch (e) {
    console.error("ERRO /tendencias/genero:", e.message);
    res.status(500).json({ erro: "Erro interno: " + e.message });
  }
});

module.exports = router;
