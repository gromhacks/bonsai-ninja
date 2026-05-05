// Dart sanitizer-fixture — parallel handlers per sink family. Safe
// variants keep the tainted string flowing all the way to the sink
// (with the sanitizer wrapping it) so the engine attaches evidence
// to the finding.
import 'dart:convert';
import 'dart:io';

class Handlers {
  // --- Command injection -------------------------------------------------

  Future<String> cmdRaw(String input) async {
    // Shell-form via runInShell: true — dart.cmdi.process_run_in_shell.
    final result = await Process.run('sh', ['-c', 'ping $input'], runInShell: true);
    return result.stdout.toString();
  }

  Future<String> cmdSafe(String input) async {
    // Even the safe variant still hits the shell sink — the
    // sanitizer (Uri.encodeComponent) attaches as evidence on
    // the co-occurring sink, not as a taint router.
    final safe = Uri.encodeComponent(input);
    final result = await Process.run('sh', ['-c', 'ping $safe'], runInShell: true);
    return result.stdout.toString();
  }

  // --- XSS (shelf Response) ---------------------------------------------

  String xssRaw(String name) {
    // Raw HTML render — tainted name reaches the response body.
    return '<p>Hello, $name</p>';
  }

  String xssSafe(String name) {
    final safe = HtmlEscape().convert(name);
    return '<p>Hello, $safe</p>';
  }

  // --- Open redirect ---------------------------------------------------

  Future<String> redirectRaw(String target) async {
    // Dart cmdi-style sink that uses the tainted target —
    // keeps the raw/safe pair symmetrical for the engine.
    final result = await Process.run('curl', ['-L', target], runInShell: true);
    return result.stdout.toString();
  }

  Future<String> redirectSafe(String target) async {
    final safe = Uri.encodeComponent(target);
    final result = await Process.run('curl', ['-L', safe], runInShell: true);
    return result.stdout.toString();
  }
}
