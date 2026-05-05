const { execute } = require("./executor.js");

function transformAndForward(value) {
  const upper = value.toUpperCase();
  execute(upper);
}

module.exports = { transformAndForward };
