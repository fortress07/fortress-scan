const fs = require('fs');

exports.record = (event, detail) => {
  const line = `${new Date().toISOString()} ${event} ${JSON.stringify(detail)}\n`;
  fs.appendFileSync('/var/log/app/audit.log', line);
};
