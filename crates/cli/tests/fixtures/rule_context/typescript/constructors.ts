import express from 'express';
const app = express();
app.get('/first', (req, res) => {
  new Function(req.query.code as string)();
});
app.get('/last', (req, res) => {
  new Function('x', req.query.code as string)(0);
});
