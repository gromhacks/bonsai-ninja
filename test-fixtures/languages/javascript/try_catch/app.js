const child_process = require("child_process");

function tainted_through_try() {
  let t;
  try {
    t = process.env.CMD;
  } catch (e) {
    t = "";
  }
  child_process.exec(t);
}

module.exports = { tainted_through_try };
