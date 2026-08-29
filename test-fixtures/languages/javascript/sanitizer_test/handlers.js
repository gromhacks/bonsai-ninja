// JavaScript sanitizer-fixture — named-function handlers so the
// adapter attributes sink + sanitizer calls to a concrete decl
// (arrow callbacks inside `app.get(...)` register only at module
// scope and don't carry an enclosing-function tag the engine can
// chain through).

const express = require('express');
const { execSync } = require('child_process');
const shellQuote = require('shell-quote');

const app = express();

// --- Command injection ---------------------------------------------------

function cmdRaw(req, res) {
  const cmd = req.query.cmd;
  res.send(execSync('ping ' + cmd).toString());
}

function cmdSafe(req, res) {
  const cmd = req.query.cmd;
  const safe = shellQuote.quote([cmd]);
  res.send(execSync('ping ' + safe).toString());
}

// --- Open redirect -------------------------------------------------------

function redirectRaw(req, res) {
  res.redirect(req.query.to);
}

function redirectSafe(req, res) {
  const to = req.query.to;
  const safe = encodeURIComponent(to);
  res.redirect('/next?to=' + safe);
}

app.get('/cmd/raw', cmdRaw);
app.get('/cmd/safe', cmdSafe);
app.get('/redirect/raw', redirectRaw);
app.get('/redirect/safe', redirectSafe);

module.exports = app;
