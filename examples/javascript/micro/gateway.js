const express = require("express");
const { getUser, updateUser } = require("./user_service");

const app = express();

// Named entry point so cross-module flow enumeration has a captured
// decl to anchor chains on. Express's `app.get(path, cb)` takes an
// arrow function that tree-sitter doesn't surface as a named decl,
// so the route handler is invisible to the workspace index. The
// route below is just a thin adapter that forwards into
// `handleRequest` — all the interesting logic (sources + sinks)
// lives in the named function so inspect's chain walker has a root.
function handleRequest(req) {
  const token = req.query.token;    // source: user input
  const action = req.query.action;  // source: user input

  const user = getUser(token);         // flows to SQL injection
  const result = updateUser(token, action);  // flows to command injection

  return { user, result };
}

app.get("/api/user", (req, res) => {
  res.json(handleRequest(req));
});

module.exports = app;
