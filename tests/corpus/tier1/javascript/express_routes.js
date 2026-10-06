const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({});

app.get('/user', (req, res) => {
  db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (e, r) => res.json(r)); // fsb-expect: FSB-SQL-001
});

app.get('/user-safe', (req, res) => {
  db.query('SELECT * FROM users WHERE name = ?', [req.query.name], (e, r) => res.json(r));
});

app.get('/user-int', (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.query('SELECT * FROM users WHERE id = ' + id, (e, r) => res.json(r));
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  cp.exec('ping -c 1 ' + host, (e, out) => res.send(out)); // fsb-expect: FSB-CMD-001
});

app.get('/ping-safe', (req, res) => {
  cp.execFile('ping', ['-c', '1', String(req.query.host)], (e, out) => res.type('text').send(out));
});

app.get('/calc', (req, res) => {
  res.json(eval(req.body.expr)); // fsb-expect: FSB-EXEC-001
});

app.get('/file', (req, res) => {
  fs.readFile(path.join('/srv/files', req.query.name), (e, data) => res.send(data)); // fsb-expect: FSB-PATH-001
});

app.get('/go', (req, res) => {
  res.redirect(req.query.next); // fsb-expect: FSB-REDIR-001
});

app.get('/go-safe', (req, res) => {
  res.redirect('/home');
});

app.get('/proxy', async (req, res) => {
  const upstream = await fetch(req.query.url); // fsb-expect: FSB-SSRF-001
  res.send(await upstream.text());
});

app.get('/hello', (req, res) => {
  const { who } = req.query;
  res.write('<p>' + who + '</p>'); // fsb-expect: FSB-XSS-001
  res.end();
});

app.get('/hello-safe', (req, res) => {
  res.write('<p>' + encodeURIComponent(req.query.who) + '</p>');
  res.end();
});

module.exports = app;
