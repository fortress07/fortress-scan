const { execSync } = require('child_process');
const yaml = require('js-yaml');
const fs = require('fs');

const target = process.argv[2];
execSync('git log ' + target); // fsb-expect: FSB-CMD-001

const config = yaml.load(fs.readFileSync('config.yml', 'utf8'));
execSync('git status');

const plugin = process.argv[3];
require(plugin); // fsb-expect: FSB-IMPORT-001

module.exports = { config };
