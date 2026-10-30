# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package Cpanel::Admin::Modules::UserTools::AppDocroot;

# App Helper primary-domain docroot (tool E): the plugin's second
# privileged entry point.
#
# Exactly one function (see _actions()): SET_APP_DOCROOT{enable} points the
# caller's PRIMARY domain at public_html/public (enable=1) or back at
# public_html (enable=0) through WHM API 1 set_primary_domain_docroot, then
# verifies the new docroot through the documented read API and audits the
# change. Both values are hard-coded; no function takes a path, glob,
# username, domain or any other key. The username always comes from
# get_caller_username(). When the domain already serves from the requested
# docroot the call is a no-op: {enable, docroot, changed:0} with no WHM
# call, no audit line and no rate-limit slot.
#
# Gates (all inside the module, first of all): policy enable_app_helper=1
# AND allow_user_app_docroot=1 (either missing means off), the caller's own
# usertools_app_helper feature via the shared Base, then the shared account
# checks (not root/system/suspended) and a 5-per-hour rate limit.
#
# The root side does NO file I/O on user paths: only the WHM call plus the
# read-API verification. The user side (UAPI app_helper_primary_check/Set)
# checks public_html/public/index.php and the public .htaccess first.
#
# Note: a caller who skips UAPI and invokes this module directly can point
# their OWN main domain at a missing folder. That is self-harm only (same
# account, no cross-account effect) and needs no further check.
use strict;
use warnings;

use parent 'Cpanel::Admin::Modules::UserTools::Base';

use JSON::PP ();

use constant _actions => ('SET_APP_DOCROOT');

# Hard-coded docroots, home-relative. Never request-supplied.
use constant {
    DOCROOT_NORMAL => 'public_html',
    DOCROOT_APP    => 'public_html/public',
};

# Overridable locations (tests drive these; production uses the defaults).
our $WHMAPI1 = '/usr/local/cpanel/bin/whmapi1';
our $UAPI    = '/usr/local/cpanel/bin/uapi';
our $RATELIMIT_DIR = '/var/cpanel/usertools/ratelimit/appdocroot';
our $AUDIT_LOG     = '/var/log/usertools.log';

# Location seams shared with Base's gates: Base owns the logic, these stay
# here so tests drive AppDocroot:: names. Each call below localizes Base's
# copy from these before delegating.
our $POLICY_FILE  = '/etc/usertools.conf';
our $USERDATA_DIR = '/var/cpanel/users';
our $SUSPEND_DIR  = '/var/cpanel/suspended';

our $MAX_DOCROOT_CHANGES_PER_HOUR = 5;

sub _is_boolean {
    my ($v) = @_;
    # Booleans only: JSON true/false, 1/0, '1'/'0'. Anything else ('yes',
    # 2, '', undef, references other than JSON booleans) is refused.
    if ( !defined $v ) {
        return;
    }
    if ( ref $v ) {
        if ( eval { $v->isa('JSON::PP::Boolean') } ) {
            return $v ? 1 : 0;
        }
        return;
    }
    if ( $v eq '1' ) {
        return 1;
    }
    if ( $v eq '0' ) {
        return 0;
    }
    return;
}

# Runs whmapi1 set_primary_domain_docroot (WHM API 1; the username whose
# primary domain changes and the home-relative docroot). Single
# implementation in Base; the binary seam stays here. List form, no shell.
# Success requires metadata.result == 1. Failure returns the metadata
# reason, truncated.
sub _whm_set_primary_docroot {
    my ( $user, $docroot ) = @_;
    return Cpanel::Admin::Modules::UserTools::Base::_whm_set_primary_docroot(
        $WHMAPI1, $user, $docroot );
}

# Reads the caller's CURRENT primary-domain docroot through the documented
# UAPI DomainInfo read API (uapi CLI as root with --user). No file I/O on
# user paths. Returns the absolute docroot or undef when unreadable. Single
# implementation in Base; the binary seam stays here.
sub _read_primary_docroot {
    my ($user) = @_;
    return Cpanel::Admin::Modules::UserTools::Base::_read_primary_docroot( $UAPI, $user );
}

# ---------------------------------------------------------------------------
# SET_APP_DOCROOT {enable}: exactly one key, a boolean.
# ---------------------------------------------------------------------------

sub SET_APP_DOCROOT {
    my ( $self, @args ) = @_;
    my ( $user, $gate_err );
    {
        local $Cpanel::Admin::Modules::UserTools::Base::POLICY_FILE = $POLICY_FILE;
        ( $user, $gate_err ) = $self->_gate_privileged(
            'usertools_app_helper',
            'enable_app_helper', 'App Helper is disabled by server policy.' );
    }
    if ( !defined $user ) {
        return { error => $gate_err };
    }
    my ( $user2, $policy_err );
    {
        local $Cpanel::Admin::Modules::UserTools::Base::POLICY_FILE = $POLICY_FILE;
        ( $user2, $policy_err ) = $self->_gate_privileged(
            'usertools_app_helper',
            'allow_user_app_docroot',
            'Serving the main domain from your app folder is disabled by server policy. '
              . "Ask your host to run: whmapi1 set_primary_domain_docroot username=$user docroot="
              . DOCROOT_APP );
    }
    if ( !defined $user2 ) {
        return { error => $policy_err };
    }
    if ( @args != 1 || ref $args[0] ne 'HASH' ) {
        return { error => 'enable is required' };
    }
    my @keys = sort keys %{ $args[0] };
    if ( @keys != 1 || $keys[0] ne 'enable' ) {
        return { error => 'only the enable key is accepted' };
    }
    my $on = _is_boolean( $args[0]{enable} );
    if ( !defined $on ) {
        return { error => 'enable must be a boolean' };
    }
    my $target = $on ? DOCROOT_APP : DOCROOT_NORMAL;

    my $acc_err;
    {
        local $Cpanel::Admin::Modules::UserTools::Base::USERDATA_DIR = $USERDATA_DIR;
        local $Cpanel::Admin::Modules::UserTools::Base::SUSPEND_DIR  = $SUSPEND_DIR;
        $acc_err = Cpanel::Admin::Modules::UserTools::Base::_gate_account($user);
    }
    if ( defined $acc_err ) {
        return { error => $acc_err };
    }

    my @pw   = getpwnam($user);
    my $home = @pw ? $pw[7] : undef;
    my $old_docroot = _read_primary_docroot($user);
    # Already serving from the target is a no-op — no WHM call, no
    # audit line, no rate-limit slot; just {changed:0}. The read above is
    # the documented UAPI read API (no writes), so checking before the rate
    # record costs nothing and keeps "X->X" out of the limit entirely.
    if ( defined $home && $home ne '' && defined $old_docroot ) {
        ( my $norm = $old_docroot ) =~ s{/+\z}{};
        if ( $norm eq "$home/$target" ) {
            return { enable => $on ? 1 : 0, docroot => $target, changed => 0 };
        }
    }

    if ( !Cpanel::Admin::Modules::UserTools::Base::_rate_check_and_record(
            $RATELIMIT_DIR, $user, undef, $MAX_DOCROOT_CHANGES_PER_HOUR ) )
    {
        return { error => 'rate limit: at most 5 primary-domain docroot changes per hour' };
    }
    my ( $ok, $err ) = _whm_set_primary_docroot( $user, $target );
    if ( !$ok ) {
        return { error => "docroot change failed: $err" };
    }
    my $live = _read_primary_docroot($user);
    my $want = ( defined $home && $home ne '' ) ? "$home/$target" : undef;
    if ( !defined $live || !defined $want || $live ne $want ) {
        return { error => 'docroot change did not take effect; contact your host' };
    }
    Cpanel::Admin::Modules::UserTools::Base::_audit(
        $AUDIT_LOG, $user,
        'primary-docroot:' . ( defined $old_docroot ? $old_docroot : 'unknown' ),
        "primary-docroot:$target" );
    return { enable => $on ? 1 : 0, docroot => $target, changed => 1 };
}

1;
