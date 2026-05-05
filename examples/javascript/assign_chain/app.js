// Assignment-chain audit fixture (JavaScript).
const express = require("express");
const child_process = require("child_process");
const { runInOtherFile } = require("./executor.js");

const CONST_OK = "ls /tmp";

function passthrough(x) { return x; }
function wrap(x) { return "wrapped:" + x; }
function combine(acc, item) { return acc + ":" + item; }

class Bag {
  constructor() { this.payload = ""; }
}

function chain_simple(req) {
  // POSITIVE
  const tmp = req.query.c1;
  child_process.exec(tmp);
}

function chain_multi_hop(req) {
  // POSITIVE
  const t1 = req.query.c2;
  const t2 = passthrough(t1);
  const t3 = wrap(t2);
  const t4 = passthrough(t3);
  child_process.exec(t4);
}

function chain_branch_join(req, cond) {
  // POSITIVE on tainted leg
  let t;
  if (cond) {
    t = req.query.c3;
  } else {
    t = "safe-static";
  }
  child_process.exec(t);
}

function chain_loop_carried(req, items) {
  // POSITIVE
  let acc = req.query.c4;
  for (const item of items) {
    acc = combine(acc, item);
  }
  child_process.exec(acc);
}

function chain_field_write(req) {
  // POSITIVE
  const bag = new Bag();
  bag.payload = req.query.c5;
  child_process.exec(bag.payload);
}

function chain_subscript_write(req) {
  // POSITIVE
  const cmds = {};
  cmds["x"] = req.query.c6;
  child_process.exec(cmds["x"]);
}

function chain_clean_constant(req) {
  // NEGATIVE
  const _unused = req.query.ignored;
  child_process.exec(CONST_OK);
}

function chain_cross_file(req) {
  // POSITIVE (cross-file)
  const t = req.query.c9;
  runInOtherFile(t);
}

module.exports = {
  chain_simple, chain_multi_hop, chain_branch_join,
  chain_loop_carried, chain_field_write, chain_subscript_write,
  chain_clean_constant, chain_cross_file,
};
