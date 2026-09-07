use CGI;
sub open_input {
    my $input = CGI::param('file');
    open(my $fh, $input);
}
sub open_three_arg_control {
    my $input = CGI::param('file');
    open(my $fh, '<', $input);
}
sub command_control {
    my $input = CGI::param('cmd');
    system($input);
}
