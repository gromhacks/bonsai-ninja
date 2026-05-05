use strict;
use warnings;
require CGI;

sub executor {
    my ($cmd) = @_;
    system($cmd);
}

sub run_cb {
    my ($cb, $value) = @_;
    $cb->($value);
}

sub pass_to_callback {
    my $t = CGI::param('cmd');
    run_cb(\&executor, $t);
}

1;
