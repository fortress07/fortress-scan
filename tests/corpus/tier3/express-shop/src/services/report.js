const { exec } = require('child_process');
const util = require('util');
const config = require('../../config/default.json');

const run = util.promisify(exec);

async function runReport(title) {
  const { stdout } = await run(config.reportCommand + ' --title ' + title);  // fsb-allow: FSB-CMD-003
  return stdout;
}

module.exports = { run: runReport };
