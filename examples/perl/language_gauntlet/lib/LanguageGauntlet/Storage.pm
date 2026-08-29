package LanguageGauntlet::Storage;
# Storage is the service boundary between the pipeline and an object-backed
# repository. The repository lives in a deeper module so package resolution,
# construction, receiver fields, aliases, and method dispatch are all real
# links on the source-to-sink path.
use strict;
use warnings;
use LanguageGauntlet::Domain::Repository;

sub wrap {
    my ($envelope) = @_;
    my $cmd = $envelope->{cmd};
    return wantarray ? ($cmd) : $cmd;
}

sub persist {
    my ($envelope) = @_;
    my $cmd = wrap($envelope);
    my $repository = LanguageGauntlet::Domain::Repository->new($cmd);
    my $alias = $repository;
    return $alias->run();
}

1;
