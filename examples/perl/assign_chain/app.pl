# Assignment-chain audit fixture (Perl).
# Uses CGI::param() function-call form (perl.source.cgi_param) +
# system() as cmdi sink, mirroring perl/mega_flow's working pattern.
# Method-style $q->param() is a separate adapter audit (Task #268).
use strict;
use warnings;
require CGI;
require './executor.pl';

my $CONST_OK = "ls /tmp";

sub passthrough { return $_[0]; }
sub wrap { return "wrapped:" . $_[0]; }
sub combine { return $_[0] . ":" . $_[1]; }

sub chain_simple {
    # POSITIVE
    my $tmp = CGI::param('c1');
    system($tmp);
}

sub chain_multi_hop {
    # POSITIVE
    my $t1 = CGI::param('c2');
    my $t2 = passthrough($t1);
    my $t3 = wrap($t2);
    my $t4 = passthrough($t3);
    system($t4);
}

sub chain_branch_join {
    my ($cond) = @_;
    # POSITIVE
    my $t;
    if ($cond) {
        $t = CGI::param('c3');
    } else {
        $t = "safe-static";
    }
    system($t);
}

sub chain_loop_carried {
    my (@items) = @_;
    # POSITIVE
    my $acc = CGI::param('c4');
    for my $item (@items) {
        $acc = combine($acc, $item);
    }
    system($acc);
}

sub chain_subscript_write {
    # POSITIVE
    my %cmds;
    $cmds{'x'} = CGI::param('c6');
    system($cmds{'x'});
}

sub chain_clean_constant {
    # NEGATIVE
    my $unused = CGI::param('ignored');
    system($CONST_OK);
}

sub chain_cross_file {
    # POSITIVE
    my $t = CGI::param('c9');
    run_in_other_file($t);
}

1;
