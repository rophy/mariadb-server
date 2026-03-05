package My::Suite::AuthK8s;

@ISA = qw(My::Suite);

use strict;

return "Not run for embedded server" if $::opt_embedded_server;

return "No AUTH_K8S plugin" unless $ENV{AUTH_K8S_SO};

sub is_default { 1 }

bless {};
