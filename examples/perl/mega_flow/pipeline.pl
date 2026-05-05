package Pipeline;
# Pipeline — exercises Perl's idiomatic flow constructs: refs,
# map / grep / sort, anonymous subs, for loops, eval-blocks,
# ternary, regex, dispatch tables.
use strict; use warnings;
require "./storage.pl";

sub StorePersist {
    my ($valid) = @_;
    return Storage::persist($valid);
}

sub orchestrate {
    my ($envelope) = @_;
    my $cmd  = $envelope->{cmd};
    my $user = $envelope->{user};

    # for loop + grep + map — filter and normalise tainted tokens.
    my @tokens;
    for my $part (split /\s+/, $cmd) {
        push @tokens, $part if length $part;
    }

    @tokens = map { my $s = $_; $s =~ s/^\s+|\s+$//g; $s } @tokens;
    @tokens = grep { length } @tokens;

    # Reduce with anonymous-sub closure — taint rides the accumulator.
    my $joiner = sub {
        my ($acc, $tok) = @_;
        return $acc eq '' ? $tok : "$acc $tok";
    };
    my $joined = '';
    for my $t (@tokens) {
        $joined = $joiner->($joined, $t);
    }

    # Dispatch via a hash of anonymous subs.
    my %routes = (
        run  => sub { my ($s) = @_; "$s" },
        eval => sub { my ($s) = @_; $s =~ s/^\s+|\s+$//g; $s },
    );
    my $kind = $envelope->{kind} // 'run';
    my $routed = exists $routes{$kind} ? $routes{$kind}->($joined) : $joined;

    # eval-block (Perl's try/catch) — taint survives the branch.
    my $valid;
    eval {
        die "empty\n" unless length $routed;
        $valid = { %$envelope, cmd => $routed, user => $user };
        1;
    } or do {
        $valid = { %$envelope, cmd => $routed // '', user => $user };
    };

    return StorePersist($valid);
}
1;
