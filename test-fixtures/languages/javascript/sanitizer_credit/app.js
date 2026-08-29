const child_process = require("child_process");
const shellescape = require("shell-escape");

function unsanitized() {
  const t = process.env.CMD;
  child_process.exec(t);
}

function sanitized() {
  const t = process.env.CMD;
  const safe = shellescape([t]);
  child_process.exec(safe);
}

module.exports = { unsanitized, sanitized };
