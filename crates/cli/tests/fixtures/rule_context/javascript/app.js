const express = require('express');
const child_process = require('child_process');
const app = express();
app.get('/redirect-encoded', (req, res) => {
  res.redirect(encodeURI(req.query.next));
});
app.get('/redirect-control', (req, res) => {
  res.redirect(req.query.next);
});
app.get('/spawn', (req, res) => {
  child_process.spawn(req.query.exe, [], {shell: false});
});
app.get('/execfile-control', (req, res) => {
  child_process.execFile(req.query.exe, []);
});
