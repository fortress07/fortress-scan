const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

async function run(command) {
  const { stdout } = await execAsync(command, { timeout: 60000 });  // fsb-allow: FSB-CMD-003
  return stdout;
}

module.exports = { run };
