# Cross-file argument flow audit fixture (Perl).
use strict;
use warnings;
require CGI;
require './pipeline.pl';

sub handler {
    # POSITIVE
    my $user = CGI::param('cmd');
    run_pipeline($user);
}

sub handler_split {
    # POSITIVE
    my $user = CGI::param('from');
    my $flag = CGI::param('flag');
    run_pipeline($user . ':' . $flag);
}

1;
