enum Kind { run, eval }

class Envelope {
  final Kind kind;
  final String cmd;
  final String user;
  final int length;
  final List<String> extras;

  Envelope({
    required this.kind,
    required this.cmd,
    required this.user,
    required this.length,
    required this.extras,
  });

  Envelope copyWith({Kind? kind, String? cmd, String? user, int? length, List<String>? extras}) =>
      Envelope(
        kind: kind ?? this.kind,
        cmd: cmd ?? this.cmd,
        user: user ?? this.user,
        length: length ?? this.length,
        extras: extras ?? this.extras,
      );
}
