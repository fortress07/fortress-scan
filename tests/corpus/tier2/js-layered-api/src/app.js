const express = require('express');
const routes = require('./routes');

const app = express();
app.use(express.json());
app.use('/users', routes.users);
app.use('/files', routes.files);
app.use('/admin', routes.admin);

module.exports = app;
