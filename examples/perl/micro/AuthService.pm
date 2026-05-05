package AuthService;
use strict;
use warnings;

use Exporter 'import';
our @EXPORT_OK = qw(verify_token run_admin_command);

sub verify_token {
    my ($token) = @_;
    my $query = "SELECT user_id FROM tokens WHERE token = '" . $token . "'";
    # sink: SQL injection via concatenation
    print $query, "\n";
    return 1;
}

sub run_admin_command {
    my ($user_id, $cmd) = @_;
    if ($user_id) {
        # sink: command injection via shell exec
        system("notify-admin " . $cmd);
    }
}

1;
