package Storage;
# Perl storage — procedural dispatch through an accessor wrapper.
# Taint rides through the wrapper into the sink.
use strict; use warnings;
require "./executor.pl";

sub wrap {
    my ($envelope) = @_;
    my $cmd = $envelope->{cmd};
    return wantarray ? ($cmd) : $cmd;
}

sub run {
    my ($envelope) = @_;
    my $cmd = wrap($envelope);
    return Executor::execute($cmd);
}

sub persist {
    my ($envelope) = @_;
    return run($envelope);
}

1;
