# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package Cpanel::Locale;

# Stub for off-server unit tests. Provides get_handle() returning a handle
# whose maketext() does [_1]-style substitution and marks output with "T:"
# so tests can prove the plugin routes strings through it. The real
# Cpanel::Locale on a cPanel server behaves the same way (without the mark).
use strict;
use warnings;

package Cpanel::Locale::TestHandle;

sub maketext {
    my ( $self, $msg, @args ) = @_;
    my $out = $msg;
    my $i   = 1;
    for my $a (@args) {
        my $n = $i++;
        $out =~ s/\[_$n\]/$a/g;
    }
    return "T:$out";
}

package Cpanel::Locale;

sub get_handle {
    return bless {}, 'Cpanel::Locale::TestHandle';
}

1;
