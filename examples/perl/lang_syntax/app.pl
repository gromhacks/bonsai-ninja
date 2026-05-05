# Language-specific syntax audit (Perl).
# Tests Perl-special forms:
#   - qx// — backtick equivalent (shell exec with interpolation)
#   - `cmd $var` — backtick (shell exec)
#   - eval $string — string-eval (compile-and-run)
# Each form should be surfaced as a Call FlowEvent so the cmdi /
# eval rules can match.
use strict;
use warnings;
require CGI;

sub handle_qx {
    # POSITIVE: qx// shell exec on tainted string.
    my $tainted = CGI::param('cmd');
    my $output = qx/ping -c 1 $tainted/;
    return $output;
}

sub handle_backtick {
    # POSITIVE: backtick form.
    my $tainted = CGI::param('cmd');
    my $output = `ping -c 1 $tainted`;
    return $output;
}

sub handle_string_eval {
    # POSITIVE: string-eval.
    my $expr = CGI::param('expr');
    my $r = eval $expr;
    return $r;
}

1;
