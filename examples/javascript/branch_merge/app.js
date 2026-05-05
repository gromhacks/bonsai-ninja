const child_process = require("child_process");

function taint_one_leg(cond) {
  let x;
  if (cond) { x = process.env.CMD; }
  else { x = "safe-static"; }
  child_process.exec(x);
}

function taint_overwritten(cond) {
  let x = process.env.CMD;
  if (cond) { x = "clean-then"; }
  else { x = "clean-else"; }
  child_process.exec(x);
}

module.exports = { taint_one_leg, taint_overwritten };
