import express, { Request, Response } from "express";
import { getUser, updateUser } from "./user_service";

const app = express();

// Named entry point so cross-module flow enumeration has a captured
// decl to anchor chains on. Express's `app.get(path, cb)` takes an
// arrow function that tree-sitter doesn't surface as a named decl,
// so the route handler is invisible to the workspace index. The
// route below is just a thin adapter that forwards into
// `handleRequest` — all the interesting logic (sources + sinks)
// lives in the named function so inspect's chain walker has a root.
function handleRequest(req: Request) {
  const token = req.query.token as string;    // source: user input
  const action = req.query.action as string;  // source: user input

  const user = getUser(token);         // flows to SQL injection
  const result = updateUser(token, action);  // flows to command injection

  return { user, result };
}

app.get("/api/user", (req: Request, res: Response) => {
  res.json(handleRequest(req));
});

export default app;
