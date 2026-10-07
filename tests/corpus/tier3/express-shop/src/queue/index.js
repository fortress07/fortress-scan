const Queue = require('bull');

const thumbnails = new Queue('thumbnails');
const mails = new Queue('mails');

module.exports = { thumbnails, mails };
