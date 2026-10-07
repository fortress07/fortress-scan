const ProductRepository = require('../repositories/product');

class CatalogService {
  constructor(repository) {
    this.repository = repository || new ProductRepository();
  }

  search(name, column) {
    return this.repository.byName(name, column);
  }

  byId(id) {
    return this.repository.byId(id);
  }
}

module.exports = new CatalogService();
