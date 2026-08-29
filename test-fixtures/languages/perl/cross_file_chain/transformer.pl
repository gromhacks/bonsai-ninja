use strict;
use warnings;
require './executor.pl';

sub transform_and_forward {
    my ($value) = @_;
    my $upper = uc($value);
    execute($upper);
}

1;
