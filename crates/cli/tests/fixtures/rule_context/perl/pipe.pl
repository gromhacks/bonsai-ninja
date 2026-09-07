use CGI;
sub pipe_input {
    my $input = CGI::param('cmd');
    open(my $fh, '|-', $input);
}
sub pipe_multi {
    my $input = CGI::param('cmd');
    open(my $fh, '-|', $input, 'fixed');
}
