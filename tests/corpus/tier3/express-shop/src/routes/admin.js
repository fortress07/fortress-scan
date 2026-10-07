const controller = require('../controllers/admin');

function mount(app) {
  app.post('/admin/report', controller.report);
  app.post('/admin/thumbnail', controller.thumbnail);
}

module.exports = { mount };
