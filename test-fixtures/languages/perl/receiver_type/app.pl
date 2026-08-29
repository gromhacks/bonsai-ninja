# Receiver-type audit fixture (Perl).
# system() is a builtin (no receiver). CGI::param is a class-method
# call.
use strict;
use warnings;
require CGI;

sub handle {
    # POSITIVE
    my $tainted = CGI::param('cmd');
    system($tainted);
}

1;
