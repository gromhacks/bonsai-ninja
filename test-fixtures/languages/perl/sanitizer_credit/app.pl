use strict;
use warnings;
use String::ShellQuote;
require CGI;

sub unsanitized {
    my $t = CGI::param('cmd');
    system($t);
}

sub sanitized {
    my $t = CGI::param('cmd');
    my $safe = String::ShellQuote::shell_quote($t);
    system($safe);
}

1;
