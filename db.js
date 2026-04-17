const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
  family: 4, // 🔥 ISSO AQUI resolve o erro
});

module.exports = pool;