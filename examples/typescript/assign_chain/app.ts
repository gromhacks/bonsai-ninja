// Assignment-chain audit fixture (TypeScript).
import { exec } from "child_process";
import { runInOtherFile } from "./executor";

const CONST_OK = "ls /tmp";

function passthrough(x: string): string { return x; }
function wrap(x: string): string { return "wrapped:" + x; }
function combine(acc: string, item: string): string { return acc + ":" + item; }

class Bag {
  payload: string = "";
}

interface Req {
  query: { [k: string]: string };
}

export function chain_simple(req: Req): void {
  // POSITIVE
  const tmp = req.query.c1;
  exec(tmp);
}

export function chain_multi_hop(req: Req): void {
  // POSITIVE
  const t1 = req.query.c2;
  const t2 = passthrough(t1);
  const t3 = wrap(t2);
  const t4 = passthrough(t3);
  exec(t4);
}

export function chain_branch_join(req: Req, cond: boolean): void {
  // POSITIVE
  let t: string;
  if (cond) {
    t = req.query.c3;
  } else {
    t = "safe-static";
  }
  exec(t);
}

export function chain_loop_carried(req: Req, items: string[]): void {
  // POSITIVE
  let acc = req.query.c4;
  for (const item of items) {
    acc = combine(acc, item);
  }
  exec(acc);
}

export function chain_field_write(req: Req): void {
  // POSITIVE
  const bag = new Bag();
  bag.payload = req.query.c5;
  exec(bag.payload);
}

export function chain_subscript_write(req: Req): void {
  // POSITIVE
  const cmds: { [k: string]: string } = {};
  cmds["x"] = req.query.c6;
  exec(cmds["x"]);
}

export function chain_clean_constant(req: Req): void {
  // NEGATIVE
  const _unused = req.query.ignored;
  exec(CONST_OK);
}

export function chain_cross_file(req: Req): void {
  // POSITIVE
  const t = req.query.c9;
  runInOtherFile(t);
}
