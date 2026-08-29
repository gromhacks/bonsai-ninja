use strict;
use warnings;
require './transformer.pl';

sub run_pipeline {
    my ($payload) = @_;
    my $wrapped = "[" . $payload . "]";
    transform_and_forward($wrapped);
}

1;
