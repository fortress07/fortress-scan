const { Pool } = require('pg');

class BaseRepository {
  constructor() {
    this.pool = new Pool();
  }

  query(sql, params) {
    return this.pool.query(sql, params);
  }

  where(clause) {
    return this.query(this.listQuery + clause);  // fsb-allow: FSB-SQL-002
  }
}

module.exports = BaseRepository;
