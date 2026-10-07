const { execFile, execSync } = require('child_process');

const { thumbnails, mails } = require('./index');

thumbnails.process(async (job) => {
  execSync('convert ' + job.data.source + ' -resize 200x200 out.png');  // fsb-expect: FSB-CMD-001
});

mails.process(async (job) => {
  execFile('sendmail', ['-t', job.data.to]);
});
