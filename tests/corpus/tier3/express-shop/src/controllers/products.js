const catalog = require('../services/catalog');
const files = require('../services/files');
const { sortColumn } = require('../util/validate');

async function list(req, res) {
  const rows = await catalog.search(req.query.name, sortColumn(req.query.sort));  // fsb-expect: FSB-SQL-001
  res.render('list', { rows });
}

async function view(req, res) {
  const product = await catalog.byId(Number(req.params.id));
  res.render('product', { product, note: req.query.note });  // fsb-expect: FSB-XSS-001
}

async function safeView(req, res) {
  res.render('safe', { note: req.query.note });
}

function download(req, res) {
  files.send(res, req.query.file);  // fsb-expect: FSB-PATH-001
}

async function byId(req, res) {
  res.json(await catalog.byId(Number(req.params.id)));
}

module.exports = { list, view, safeView, download, byId };
