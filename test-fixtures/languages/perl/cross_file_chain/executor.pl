use strict;
use warnings;

sub execute {
    my ($cmd) = @_;
    # POSITIVE (terminal cross-file sink)
    system($cmd);
}

1;
