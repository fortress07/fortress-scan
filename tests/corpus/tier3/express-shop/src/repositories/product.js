const BaseRepository = require('./base');
const config = require('../../config/default.json');

class ProductRepository extends BaseRepository {
  constructor() {
    super();
    this.listQuery = config.listQuery;
  }

  byName(name, column) {
    return this.where("name ILIKE '%" + name + "%' ORDER BY " + column);
  }

  byId(id) {
    return this.query('SELECT * FROM products WHERE id = $1', [id]);
  }
}

module.exports = ProductRepository;
