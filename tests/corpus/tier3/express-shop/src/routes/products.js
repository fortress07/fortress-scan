const controller = require('../controllers/products');

function mount(app) {
  app.get('/products', controller.list);
  app.get('/products/view', controller.view);
  app.get('/products/safe', controller.safeView);
  app.get('/products/download', controller.download);
  app.get('/products/:id', controller.byId);
}

module.exports = { mount };
