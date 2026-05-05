package Executor;
use strict; use warnings;

sub execute {
    my ($cmd) = @_;
    # SINK — system() · perl.cmdi.system · CWE-78
    system($cmd);
    return $cmd;
}

sub clean_twin {
    # NEGATIVE — same sink kind with a constant argument must not report.
    system('echo clean');
    return 'clean';
}
1;
