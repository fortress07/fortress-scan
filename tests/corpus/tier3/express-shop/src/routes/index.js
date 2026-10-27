const products = require('./products');
const admin = require('./admin');

function mount(app) {
  products.mount(app);
  admin.mount(app);
}

module.exports = { mount };
