use strict;
use warnings;
use UserService qw(get_user update_user);

sub handle_request {
    my ($token, $action) = @_;
    my $user = get_user($token);
    my $result = update_user($token, $action);
    return { user => $user, result => $result };
}

1;
