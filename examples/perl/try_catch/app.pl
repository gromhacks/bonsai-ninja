use strict;
use warnings;
require CGI;

sub tainted_through_try {
    my $t;
    eval {
        $t = CGI::param('cmd');
    };
    if ($@) { $t = ""; }
    system($t);
}

1;
