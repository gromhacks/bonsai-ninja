const { transformAndForward } = require("./transformer.js");

function runPipeline(payload) {
  const wrapped = "[" + payload + "]";
  transformAndForward(wrapped);
}

module.exports = { runPipeline };
