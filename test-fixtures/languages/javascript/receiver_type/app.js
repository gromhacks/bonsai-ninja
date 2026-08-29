// Receiver-type audit fixture (JavaScript).
// `child_process.exec(tainted)` — module-namespace receiver.
// Tests source-->cmdi-sink path; the JS adapter's process.env
// read flows into the named bound var into exec's tainted arg.
const child_process = require("child_process");

function handle() {
  // POSITIVE
  const tainted = process.env.CMD;
  child_process.exec(tainted);
}

module.exports = { handle };
