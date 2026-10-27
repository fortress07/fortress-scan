const path = require('path');
const express = require('express');

const routes = require('./routes');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
routes.mount(app);

module.exports = app;
