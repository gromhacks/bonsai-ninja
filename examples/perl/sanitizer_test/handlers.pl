# Perl sanitizer-fixture — parallel handlers per sink family.
use strict;
use warnings;
use HTML::Entities qw(encode_entities);
use URI::Escape    qw(uri_escape);
use String::ShellQuote;
use DBI;

# --- Command injection ---------------------------------------------------
sub cmd_raw {
    my ($input) = @_;
    return system("ping " . $input);
}

sub cmd_safe {
    my ($input) = @_;
    my $safe = shell_quote($input);
    return system("ping " . $safe);
}

# --- SQL injection -------------------------------------------------------
sub sql_raw {
    my ($dbh, $user_id) = @_;
    return $dbh->do("SELECT * FROM users WHERE id = '" . $user_id . "'");
}

sub sql_safe {
    my ($dbh, $user_id) = @_;
    my $sth = $dbh->prepare("SELECT * FROM users WHERE id = ?");
    $sth->execute($user_id);
    return $sth;
}

# --- XSS -----------------------------------------------------------------
sub xss_raw {
    my ($name) = @_;
    return "<p>Hello, " . $name . "</p>";
}

sub xss_safe {
    my ($name) = @_;
    my $safe = encode_entities($name);
    return "<p>Hello, " . $safe . "</p>";
}

# --- Open redirect -------------------------------------------------------
sub redirect_safe {
    my ($target) = @_;
    my $safe = uri_escape($target);
    return "/next?to=" . $safe;
}

1;
