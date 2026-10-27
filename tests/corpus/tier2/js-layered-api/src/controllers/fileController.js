const path = require('path');
const { services } = require('../services');

exports.download = (req, res) => {
  const stream = services.files.open(req.query.file); // fsb-expect: FSB-PATH-001
  stream.on('error', () => res.sendStatus(404));
  stream.pipe(res);
};

exports.preview = (req, res) => {
  const stream = services.files.open(path.basename(req.query.file));
  stream.on('error', () => res.sendStatus(404));
  stream.pipe(res);
};
