# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package Cpanel::Admin::Base;

# Stub for off-server unit tests. The real Cpanel::Admin::Base (cPanel server)
# provides get_caller_username() and friends; tests call
# the module's functions with blessed fakes instead.
use strict;
use warnings;

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

sub get_caller_username {
    die "stub: override get_caller_username in tests\n";
}

1;
