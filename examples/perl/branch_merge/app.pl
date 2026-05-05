use strict;
use warnings;
require CGI;

sub taint_one_leg {
    my ($cond) = @_;
    my $x;
    if ($cond) { $x = CGI::param('cmd'); }
    else { $x = "safe-static"; }
    system($x);
}

sub taint_overwritten {
    my ($cond) = @_;
    my $x = CGI::param('cmd');
    if ($cond) { $x = "clean-then"; }
    else { $x = "clean-else"; }
    system($x);
}

1;
