const reports = require('../services/report');
const { thumbnails } = require('../queue');

async function report(req, res) {
  await reports.run(req.body.title);  // fsb-expect: FSB-CMD-001
  res.status(202).end();
}

async function thumbnail(req, res) {
  await thumbnails.add({ source: req.body.source });
  res.status(202).end();
}

module.exports = { report, thumbnail };
