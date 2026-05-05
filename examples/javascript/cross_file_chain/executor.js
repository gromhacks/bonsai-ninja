const child_process = require("child_process");

function execute(cmd) {
  // POSITIVE (terminal cross-file sink)
  child_process.exec(cmd);
}

module.exports = { execute };
