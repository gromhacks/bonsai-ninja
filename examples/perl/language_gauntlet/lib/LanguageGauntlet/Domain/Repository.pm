package LanguageGauntlet::Domain::Repository;

use strict;
use warnings;
use LanguageGauntlet::Executor;

sub new {
    my ($class, $cmd) = @_;
    return bless { cmd => $cmd }, $class;
}

sub command {
    my ($self) = @_;
    return $self->{cmd};
}

sub run {
    my ($self) = @_;
    my $cmd = $self->command();
    return LanguageGauntlet::Executor::execute($cmd);
}

1;
