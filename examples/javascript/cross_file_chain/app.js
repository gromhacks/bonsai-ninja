// Cross-file argument flow audit fixture (JavaScript).
const { runPipeline } = require("./pipeline.js");

function handler() {
  // POSITIVE: source in app.js, sink three modules away.
  const user = process.env.CMD;
  runPipeline(user);
}

function handlerSplit() {
  // POSITIVE: split-arg cross-file flow.
  const user = process.env.FROM;
  const flag = process.env.FLAG;
  runPipeline(user + ":" + flag);
}

module.exports = { handler, handlerSplit };
