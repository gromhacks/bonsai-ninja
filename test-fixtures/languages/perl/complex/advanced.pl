use strict;
use warnings;

sub find_user {
    my ($users, $id) = @_;
    if (exists $users->{$id}) {
        return $users->{$id};
    }
    return undef;
}

sub load_all_users {
    my %users;
    eval {
        for my $i (0..9) {
            $users{$i} = "user_$i";
        }
    };
    if ($@) {
        print "load failed: $@\n";
        return ();
    }
    return %users;
}

sub escape_sql {
    my ($input) = @_;
    $input =~ s/'/''/g;
    return $input;
}

sub process_batch {
    my (@tokens) = @_;
    for my $token (@tokens) {
        next if $token eq "";
        if ($token =~ /^admin_/) {
            run_admin($token);
        } else {
            run_user($token);
        }
    }
}

sub run_admin {
    my ($token) = @_;
    system("admin-task " . $token);
}

sub run_user {
    my ($token) = @_;
    system("user-task " . $token);
}

1;
