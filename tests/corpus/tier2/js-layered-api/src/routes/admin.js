const router = require('express').Router();
const { run } = require('../util/shell');
const audit = require('../util/audit');

router.post('/backup', (req, res) => {
  const target = req.body.target;
  run(`tar czf /backups/${target}.tgz /srv/data`) // fsb-expect: FSB-CMD-001
    .then(() => res.sendStatus(204))
    .catch(() => res.sendStatus(500));
});

router.post('/rotate', (req, res) => {
  const days = parseInt(req.body.days, 10) || 7;
  run('find /var/log/app -mtime +' + days + ' -delete').then(() => res.sendStatus(204));
});

router.post('/note', (req, res) => {
  audit.record('admin note', req.body.note);
  res.sendStatus(204);
});

module.exports = router;
