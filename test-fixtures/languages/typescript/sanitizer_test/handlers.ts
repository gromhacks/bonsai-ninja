// TypeScript sanitizer-fixture — named function handlers so the
// adapter resolves a concrete decl per sink + sanitizer call (arrow
// callbacks inside `app.get(...)` register at module scope only).
import express, { Request, Response } from 'express';
import { execSync } from 'child_process';
import * as shellQuote from 'shell-quote';

const app = express();

function cmdRaw(req: Request, res: Response): void {
  const cmd = req.query.cmd as string;
  res.send(execSync('ping ' + cmd).toString());
}

function cmdSafe(req: Request, res: Response): void {
  const cmd = req.query.cmd as string;
  const safe = shellQuote.quote([cmd]);
  res.send(execSync('ping ' + safe).toString());
}

function redirectRaw(req: Request, res: Response): void {
  res.redirect(req.query.to as string);
}

function redirectSafe(req: Request, res: Response): void {
  const to = req.query.to as string;
  const safe = encodeURIComponent(to);
  res.redirect('/next?to=' + safe);
}

app.get('/cmd/raw', cmdRaw);
app.get('/cmd/safe', cmdSafe);
app.get('/redirect/raw', redirectRaw);
app.get('/redirect/safe', redirectSafe);

export default app;
