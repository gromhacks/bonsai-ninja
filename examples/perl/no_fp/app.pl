use strict;
use warnings;
require CGI;

my $CONST_OK = "ls /tmp";

sub decoy {
    my $unused = CGI::param('ignored');
    system($CONST_OK);
}

sub unrelated_chain {
    my $a = "hello";
    return uc($a);
}

1;
