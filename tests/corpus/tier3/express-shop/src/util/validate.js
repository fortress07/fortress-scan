const COLUMNS = ['name', 'price', 'created_at'];

function sortColumn(value) {
  return COLUMNS.includes(value) ? value : 'name';
}

module.exports = { sortColumn };
