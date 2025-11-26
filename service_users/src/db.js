const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.POSTGRES_USER || 'user',
  host: process.env.DB_HOST || 'db',
  database: process.env.POSTGRES_DB || 'task_management_db',
  password: process.env.POSTGRES_PASSWORD || 'password',
  port: 5432,
});

pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};
