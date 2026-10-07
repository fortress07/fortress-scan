const { services } = require('../services');

exports.search = async (req, res) => {
  const rows = await services.users.findByName(req.query.name); // fsb-expect: FSB-SQL-001
  res.json(rows);
};

exports.byId = async (req, res) => {
  const rows = await services.users.findById(req.params.id);
  res.json(rows);
};

exports.sorted = async (req, res) => {
  const column = req.query.sort;
  const rows = await services.users.listSorted(column); // fsb-expect: FSB-SQL-001
  res.json(rows);
};
