// mega_flow JS entry — reads an interactive stdin line via the
// readline/promises API, then dispatches the tainted value through
// a pipeline that exercises every idiomatic JS flow construct
// (async/await, destructuring, rest/spread, closures, array methods,
// switch, template literals, optional chaining, classes, generators).
const readline = require("readline/promises");
const { orchestrate } = require("./pipeline");

async function handle_request() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  // SOURCE — readline.Interface.question (javascript.source.readline_question)
  // returns the tainted stdin line as a Promise<string>.
  const raw = await rl.question("cmd: ");
  const user = "anon";

  // Template literal + spread + optional chaining — taint rides
  // through the envelope's cmd field.
  const envelope = {
    kind: "run",
    cmd: `${raw}`,
    user,
    length: raw?.length ?? 0,
    extras: [],
  };

  rl.close();
  return await orchestrate(envelope);
}

handle_request().then((out) => console.log(out));

module.exports = { handle_request };
