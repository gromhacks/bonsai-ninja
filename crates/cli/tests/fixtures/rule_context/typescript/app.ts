import express from 'express';
import {spawn, execFile} from 'child_process';
const app = express();
app.get('/encoded', (req, res) => {
  res.redirect(encodeURI(req.query.next as string));
});
app.get('/direct', (req, res) => {
  res.redirect(req.query.next as string);
});
app.get('/spawn', (req, res) => {
  spawn(req.query.exe as string, [], {shell: false});
});
app.get('/execfile-control', (req, res) => {
  execFile(req.query.exe as string, []);
});
