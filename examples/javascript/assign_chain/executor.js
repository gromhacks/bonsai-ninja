const child_process = require("child_process");

function runInOtherFile(cmd) {
  // POSITIVE (cross-file)
  child_process.exec(cmd);
}

module.exports = { runInOtherFile };
