# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package Cpanel::AdminBin::Call;

# Stub for off-server unit tests. Records every call; tests program the
# canned admin-side response per function name.
use strict;
use warnings;

our @CALLS;
our %RESPOND;

sub call {
    my ( $ns, $mod, $action, @args ) = @_;
    push @CALLS, { ns => $ns, mod => $mod, action => $action, args => \@args };
    my $fn = $RESPOND{$action};
    if ( ref $fn eq 'CODE' ) {
        return $fn->(@args);
    }
    return exists $RESPOND{$action} ? $RESPOND{$action} : { mode => 'jailed' };
}

sub reset {
    @CALLS  = ();
    %RESPOND = ();
}

1;
