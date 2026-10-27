const fs = require('fs');
const path = require('path');
const config = require('../../config/default.json');

function send(res, name) {
  fs.createReadStream(path.join(config.uploadRoot, name)).pipe(res);
}

function sendChecked(res, name) {
  fs.createReadStream(path.join(config.uploadRoot, path.basename(name))).pipe(res);
}

module.exports = { send, sendChecked };
