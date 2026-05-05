const child_process = require("child_process");

function executor(cmd) {
  child_process.exec(cmd);
}

function run(callback, value) {
  callback(value);
}

function pass_to_callback() {
  const t = process.env.CMD;
  run(executor, t);
}

module.exports = { pass_to_callback };
