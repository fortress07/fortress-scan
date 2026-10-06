const fs = require('fs');
const path = require('path');

class FileService {
  constructor(root) {
    this.root = root;
  }

  open(name) {
    return fs.createReadStream(path.join(this.root, name));
  }
}

module.exports = FileService;
