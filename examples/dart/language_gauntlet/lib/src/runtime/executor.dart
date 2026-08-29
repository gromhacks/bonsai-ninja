import 'dart:io';

String execute(String cmd) {
  // SINK — Process.runSync with runInShell: true · dart.cmdi.process_runsync_in_shell · CWE-78
  Process.runSync('sh', ['-c', cmd], runInShell: true);
  return cmd;
}

String cleanTwin() {
  // NEGATIVE — same sink kind with a constant argument must not report.
  Process.runSync('sh', ['-c', 'echo clean'], runInShell: true);
  return 'clean';
}
