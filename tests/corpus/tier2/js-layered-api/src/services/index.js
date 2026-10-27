const UserService = require('./userService');
const FileService = require('./fileService');
const UserRepository = require('../db/userRepository');
const pool = require('../db/pool');

function createServices(db) {
  const userRepo = new UserRepository(db);
  return {
    users: new UserService(userRepo),
    files: new FileService('/srv/uploads'),
  };
}

const services = createServices(pool);

module.exports = { services, createServices };
