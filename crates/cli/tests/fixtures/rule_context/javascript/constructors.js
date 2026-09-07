const express = require('express');
const app = express();
app.get('/first', (req, res) => {
  new Function(req.query.code)();
});
app.get('/last', (req, res) => {
  new Function('x', req.query.code)(0);
});
