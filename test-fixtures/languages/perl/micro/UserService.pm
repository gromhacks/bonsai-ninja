package UserService;
use strict;
use warnings;
use AuthService qw(verify_token run_admin_command);

use Exporter 'import';
our @EXPORT_OK = qw(get_user update_user);

sub get_user {
    my ($token) = @_;
    return verify_token($token);
}

sub update_user {
    my ($token, $action) = @_;
    my $user_id = verify_token($token);
    if (defined $user_id) {
        run_admin_command($user_id, $action);
    }
    return $user_id;
}

1;
