# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package Cpanel::Admin::Modules::UserTools::Base;

# Shared base for the plugin's privileged Admin modules.
#
# Every privileged function runs its gates FIRST, before any rate-limit or
# state change: the policy kill-switch from /etc/usertools.conf and the
# caller's own feature via the documented inherited
# cpuser_has_feature_or_die(). A cPanel user can invoke Admin modules
# directly, bypassing UAPI, so no module ever trusts the caller or the UAPI
# layer. This applies to every privileged function, present and future.
#
# Subclasses (Shell, AppDocroot) alias these package variables to their own
# globs so existing test seams keep working, and wrap _gate_privileged()
# with their policy key and disabled message.
use strict;
use warnings;

use parent 'Cpanel::Admin::Base';

use Fcntl qw(:flock);

# Overridable locations (tests drive these; production uses the defaults).
our $POLICY_FILE   = '/etc/usertools.conf';
our $PRIVATE_FILE  = '/etc/usertools.private.conf';
our $RATELIMIT_DIR = '/var/cpanel/usertools/ratelimit';
our $AUDIT_LOG     = '/var/log/usertools.log';
our $SUSPEND_DIR   = '/var/cpanel/suspended';
our $USERDATA_DIR  = '/var/cpanel/users';
our $GROUP_FILE    = '/etc/group';

our $MAX_CHANGES_PER_HOUR = 10;

sub _valid_username {
    my ($user) = @_;
    return ( defined $user && $user =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/ ) ? 1 : 0;
}

sub _read_policy {
    my ($path) = @_;
    $path = $POLICY_FILE unless defined $path;
    my %values;
    if ( open my $fh, '<', $path ) {
        while ( my $line = <$fh> ) {
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '' || $line =~ /^[#;]/ || $line =~ /^\[/;
            next unless $line =~ /=/;
            my ( $k, $v ) = split /=/, $line, 2;
            $k =~ s/^\s+|\s+$//g;
            $v =~ s/\s*[;#].*$//;
            $v =~ s/^\s+|\s+$//g;
            $values{$k} = $v if $k ne '';
        }
        close $fh;
    }
    return \%values;
}

# Server-side gates every privileged function runs FIRST (before the rate
# limit is touched): the named policy key must be literally '1' (missing
# means off) and the caller must hold the named feature. Returns
# ($user, undef) on success, (undef, $error) on refusal.
sub _gate_privileged {
    my ( $self, $wants_feature, $policy_key, $disabled_msg ) = @_;
    $policy_key   = 'enable_shell' unless defined $policy_key;
    $disabled_msg = 'Access is disabled by server policy.' unless defined $disabled_msg;
    my $user = $self->get_caller_username();
    if ( !_valid_username($user) ) {
        return ( undef, 'invalid caller' );
    }
    my $policy = _read_policy();
    if ( ( $policy->{$policy_key} // '' ) ne '1' ) {
        return ( undef, $disabled_msg );
    }
    my $has_it = eval { $self->cpuser_has_feature_or_die($wants_feature); 1 };
    if ( !$has_it ) {
        return ( undef, 'This feature is not enabled for your account.' );
    }
    return ( $user, undef );
}

# Account-state refusals shared by every privileged change: root/system,
# non-cPanel account, suspended. Returns undef when the change may proceed,
# otherwise the refusal message.
sub _gate_account {
    my ($user) = @_;
    my @pw = getpwnam($user);
    if ( !@pw ) {
        return 'unknown account';
    }
    my $uid = $pw[2];
    if ( $user eq 'root' || $uid < 1000 ) {
        return 'refusing change for a root/system account';
    }
    if ( !-e "$USERDATA_DIR/$user" ) {
        return 'not a cPanel account';
    }
    if ( -e "$SUSPEND_DIR/$user" ) {
        return 'refusing change for a suspended account';
    }
    return undef;
}

sub _rate_check_and_record {
    my ( $dir, $user, $now, $max ) = @_;
    # Returns 1 if allowed (and records this change), 0 if over the limit.
    $now = time() unless defined $now;
    $max = $MAX_CHANGES_PER_HOUR unless defined $max;
    eval { require File::Path; File::Path::make_path( $dir, { mode => 0700 } ); };
    return 0 if $@;
    my $file = "$dir/$user";
    if ( $file !~ m{^/\S+$} || $user =~ m{/} ) {
        return 0;
    }
    open my $fh, '+>>', $file or return 0;
    flock( $fh, LOCK_EX | LOCK_NB ) or do {
        close $fh;
        return 0;
    };
    seek( $fh, 0, 0 );
    my @recent = grep { $_ > $now - 3600 } map { 0 + $_ } grep { /^\d+$/ } <$fh>;
    if ( @recent >= $max ) {
        close $fh;
        return 0;
    }
    truncate( $fh, 0 );
    seek( $fh, 0, 0 );
    print $fh join( "\n", @recent, $now ) . "\n";
    close $fh;
    chmod 0600, $file;
    return 1;
}

sub _audit {
    my ( $log, $user, $old, $new ) = @_;
    my @t = gmtime();
    my $ts = sprintf( "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0] );
    if ( open my $fh, '>>', $log ) {
        flock( $fh, LOCK_EX );
        print $fh "$ts $user $old->$new\n";
        close $fh;
        chmod 0600, $log;
    }
    return;
}

# ---------------------------------------------------------------------------
# Shared root-side WHM helpers: the primary-docroot switch and the
# account-creation hook both call WHM API 1 and verify through the read API.
# Binaries travel as explicit parameters so each caller keeps its own test
# seam; $what names the function in error strings. List form, no shell.
# ---------------------------------------------------------------------------

sub _whm_call_json {
    my ( $whmapi1, $what, @args ) = @_;
    # Returns (1, $decoded) or (0, $error).
    my $fh;
    if ( !open $fh, '-|', $whmapi1, '--output=json', @args ) {
        return ( 0, "cannot run whmapi1: $!" );
    }
    local $/;
    my $out = <$fh>;
    close $fh;
    if ( $? != 0 || !defined $out ) {
        return ( 0, "$what did not run cleanly" );
    }
    require JSON::PP;
    my $data = eval { JSON::PP->new()->decode($out) };
    if ( $@ || ref $data ne 'HASH' ) {
        return ( 0, "$what returned an unreadable reply" );
    }
    return ( 1, $data );
}

sub _whm_metadata_result {
    my ($data) = @_;
    # WHM API 1 success is metadata.result == 1 (never a regex over the
    # payload). Returns (1, '') or (0, $truncated_reason).
    my $meta = ref $data eq 'HASH' && ref $data->{metadata} eq 'HASH' ? $data->{metadata} : undef;
    if ( $meta && ( ( $meta->{result} // 0 ) == 1 ) ) {
        return ( 1, '' );
    }
    my $reason = $meta ? ( $meta->{reason} // 'unknown error' ) : 'unknown error';
    return ( 0, substr( "$reason", 0, 200 ) );
}

sub _whm_set_primary_docroot {
    my ( $whmapi1, $user, $docroot ) = @_;
    my ( $ok, $data ) = _whm_call_json(
        $whmapi1, 'set_primary_domain_docroot',
        'set_primary_domain_docroot', "username=$user", "docroot=$docroot" );
    if ( !$ok ) {
        return ( 0, $data );
    }
    return _whm_metadata_result($data);
}

sub _find_main_domain {
    my ($node) = @_;
    # On cPanel 11.138, DomainInfo::domains_data returns result.data = {
    # main_domain => {HASH}, addon_domains => [..], parked_domains => [..],
    # sub_domains => [..] } where main_domain is a hash with `domain`,
    # `documentroot`, `type => 'main_domain'`, etc. Scalar main_domain is
    # kept only as a fallback.
    return undef unless ref $node;
    if ( ref $node eq 'HASH' ) {
        if ( ref $node->{main_domain} eq 'HASH' ) {
            my $md = $node->{main_domain};
            if ( defined $md->{domain} && !ref $md->{domain} && $md->{domain} ne '' ) {
                return $md->{domain};
            }
        }
        if ( defined $node->{main_domain} && !ref $node->{main_domain} && $node->{main_domain} ne '' ) {
            return $node->{main_domain};
        }
        for my $v ( values %{$node} ) {
            my $found = _find_main_domain($v);
            return $found if defined $found;
        }
        return undef;
    }
    if ( ref $node eq 'ARRAY' ) {
        for my $v ( @{$node} ) {
            my $found = _find_main_domain($v);
            return $found if defined $found;
        }
    }
    return undef;
}

sub _find_main_docroot {
    my ( $node, $main ) = @_;
    return undef unless defined $node;
    if ( ref $node eq 'HASH' ) {
        if ( ref $node->{main_domain} eq 'HASH' ) {
            my $md = $node->{main_domain};
            if ( defined $md->{documentroot} && !ref $md->{documentroot} ) {
                if ( !defined $main || ( defined $md->{domain} && lc( $md->{domain} ) eq lc($main) ) ) {
                    return $md->{documentroot};
                }
            }
        }
        if ( defined $node->{domain} && defined $node->{documentroot} ) {
            if ( defined $main && lc( $node->{domain} ) eq lc($main) ) {
                return $node->{documentroot};
            }
        }
        for my $v ( values %{$node} ) {
            my $found = _find_main_docroot( $v, $main );
            return $found if defined $found;
        }
        return undef;
    }
    if ( ref $node eq 'ARRAY' ) {
        for my $v ( @{$node} ) {
            my $found = _find_main_docroot( $v, $main );
            return $found if defined $found;
        }
    }
    return undef;
}

sub _read_primary_docroot {
    my ( $uapi, $user ) = @_;
    # The caller's CURRENT primary-domain docroot through the documented
    # UAPI DomainInfo read API (uapi CLI with --user; root may impersonate).
    # No file I/O on user paths. Absolute docroot or undef when unreadable.
    my $fh;
    if ( !open $fh, '-|', $uapi, "--user=$user", '--output=json', 'DomainInfo', 'domains_data' ) {
        return undef;
    }
    local $/;
    my $out = <$fh>;
    close $fh;
    if ( $? != 0 || !defined $out ) {
        return undef;
    }
    require JSON::PP;
    my $data = eval { JSON::PP->new()->decode($out) };
    if ( $@ || ref $data ne 'HASH' ) {
        return undef;
    }
    my $main = _find_main_domain($data);
    if ( !defined $main ) {
        return undef;
    }
    return _find_main_docroot( $data, $main );
}

1;
