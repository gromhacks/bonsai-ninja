use strict;
use warnings;

sub run_in_other_file {
    my ($cmd) = @_;
    # POSITIVE (cross-file)
    system($cmd);
}

1;
