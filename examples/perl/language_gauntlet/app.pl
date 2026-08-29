#!/usr/bin/env perl
# language_gauntlet Perl entry — reads CGI param, then dispatches through a
# pipeline that exercises every idiomatic Perl flow construct (refs,
# dispatch via method, anonymous subs, map/grep, for-loops, unless,
# local, eval-blocks, wantarray).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";

use LanguageGauntlet::Pipeline;

sub handle_request {
    # SOURCE — CGI::param (function call form) — HTTP query parameter.
    # Matched by perl.source.cgi_param (call-kind).
    require CGI;
    my $raw = CGI::param('cmd');
    $raw = defined $raw ? $raw : '';
    my $user = defined $ENV{USER} ? $ENV{USER} : 'anon';
    local $ENV{LANGUAGE_GAUNTLET_AUDIT} = '1';

    # Anonymous hash ref holds the tainted cmd + metadata.
    my $envelope = {
        kind   => 'run',
        cmd    => "$raw",
        user   => $user,
        length => length($raw),
        extras => [ $raw ],
    };

    return LanguageGauntlet::Pipeline::orchestrate($envelope);
}

handle_request();
print "ok\n";
