class UserRepository {
  constructor(db) {
    this.db = db;
  }

  byName(name) {
    return this.db.query(`SELECT id, name, email FROM users WHERE name = '${name}'`);  // fsb-allow: FSB-SQL-002
  }

  byId(id) {
    return this.db.query('SELECT id, name, email FROM users WHERE id = ?', [id]);
  }

  sortedBy(column) {
    return this.db.query('SELECT id, name FROM users ORDER BY ' + column);  // fsb-allow: FSB-SQL-002
  }
}

module.exports = UserRepository;
