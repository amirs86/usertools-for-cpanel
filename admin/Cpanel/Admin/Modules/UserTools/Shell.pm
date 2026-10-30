# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package Cpanel::Admin::Modules::UserTools::Shell;

# Manage Shell (tool A): the plugin's ONLY privileged entry point.
#
# Exactly two functions (see _actions()): GET_SHELL reads the caller's login
# shell; SET_SHELL{mode} sets it through whmapi1 modifyacct's documented
# `shell` parameter (never usermod, never /etc/passwd edits, never
# jaildefaultshell). The username always comes from get_caller_username();
# no function takes a path, glob, username or any other key.
#
# The only files touched are all root-owned and outside /home: the policy
# file, the rate-limit store and the audit log. No file I/O on user paths.
use strict;
use warnings;

use parent 'Cpanel::Admin::Base';

use Cpanel::Admin::Modules::UserTools::Base ();
my $BASE = 'Cpanel::Admin::Modules::UserTools::Base';

use Fcntl qw(:flock);

use constant _actions => (
    'GET_SHELL',
    'SET_SHELL',
);

# Modes and their explicit login shells. Never rely on the server default.
use constant {
    SHELL_NOSHELL   => '/usr/local/cpanel/bin/noshell',
    SHELL_JAILSHELL => '/usr/local/cpanel/bin/jailshell',
    SHELL_BASH      => '/bin/bash',
};

# Overridable locations (tests drive these; production uses the defaults).
our $POLICY_FILE   = '/etc/usertools.conf';
our $PRIVATE_FILE  = '/etc/usertools.private.conf';
our $RATELIMIT_DIR = '/var/cpanel/usertools/ratelimit';
our $AUDIT_LOG     = '/var/log/usertools.log';
our $SUSPEND_DIR   = '/var/cpanel/suspended';
our $USERDATA_DIR  = '/var/cpanel/users';
our $GROUP_FILE    = '/etc/group';
our $WHMAPI1       = '/usr/local/cpanel/bin/whmapi1';
our $CPANEL_CONFIG = '/var/cpanel/cpanel.config';

our $MAX_CHANGES_PER_HOUR = 10;

# ---------------------------------------------------------------------------
# Small helpers (pure where possible so tests can drive them)
# ---------------------------------------------------------------------------

sub _valid_username {
    my ($user) = @_;
    return Cpanel::Admin::Modules::UserTools::Base::_valid_username($user);
}

sub _read_policy {
    my ($path) = @_;
    # Base owns the parser; the location seam stays here so tests keep
    # driving Shell::$POLICY_FILE.
    local $Cpanel::Admin::Modules::UserTools::Base::POLICY_FILE = $POLICY_FILE;
    return Cpanel::Admin::Modules::UserTools::Base::_read_policy($path);
}

sub _csv_list {
    my ($text) = @_;
    return () unless defined $text && $text ne '';
    return map { s/^\s+|\s+$//gr } split /,/, $text;
}

# Server-side gates every privileged function runs FIRST (before the rate
# limit is touched): the policy kill-switch and the caller's own feature.
# A cPanel user can invoke this module directly, bypassing UAPI, so the
# module never trusts the caller or the UAPI layer. Applies to every future
# privileged function too. Implemented once in
# Base; this wrapper pins the Shell policy key and
# message so existing behaviour is unchanged.
sub _gate_privileged {
    my ( $self, $wants_feature ) = @_;
    local $Cpanel::Admin::Modules::UserTools::Base::POLICY_FILE = $POLICY_FILE;
    return Cpanel::Admin::Modules::UserTools::Base::_gate_privileged(
        $self, $wants_feature,
        'enable_shell', 'Shell access is disabled by server policy.' );
}

sub _mode_to_shell {
    my ($mode) = @_;
    if ( $mode eq 'disabled' ) {
        return ( 0, SHELL_NOSHELL );
    }
    if ( $mode eq 'jailed' ) {
        return ( 1, SHELL_JAILSHELL );
    }
    if ( $mode eq 'normal' ) {
        return ( 1, SHELL_BASH );
    }
    return;
}

sub _shell_to_mode {
    my ($shell) = @_;
    return 'disabled' if defined $shell && $shell eq SHELL_NOSHELL;
    return 'jailed'   if defined $shell && $shell eq SHELL_JAILSHELL;
    return 'normal'   if defined $shell && $shell eq SHELL_BASH;
    return 'other';
}

sub _jaildefaultshell_on {
    my ($path) = @_;
    # On cPanel 11.138, WHM API 1 modifyacct (https://api.docs.cpanel.net/specifications/whm.openapi/account-management/accounts-modifyacct)
    # documents `HASSHELL` and `shell`, but in practice `modifyacct` ignores
    # `shell=` and applies the server default shell (`/bin/bash` when the
    # "Use cPanel® jailshell by default" tweak `jaildefaultshell` is 0, and
    # `/usr/local/cpanel/bin/jailshell` when it is 1; see
    # https://docs.cpanel.net/knowledge-base/accounts/virtfs-jailed-shell/).
    # WHM's own "Manage Shell Access" UI calls internal Perl modules, which
    # we never call. Therefore, when `cpanel.config` explicitly sets
    # `jaildefaultshell=0`, `jailed` cannot be granted via official APIs and
    # must be hidden/refused. If the file or key is absent (e.g. minimal
    # test fixtures), we return 1 and rely on the mandatory fail-closed
    # read-back + rollback in SET_SHELL.
    $path = $CPANEL_CONFIG unless defined $path;
    if ( open my $fh, '<', $path ) {
        while ( my $line = <$fh> ) {
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '' || $line =~ /^[#;]/;
            next unless $line =~ /=/;
            my ( $k, $v ) = split /=/, $line, 2;
            $k =~ s/^\s+|\s+$//g;
            $v =~ s/\s*[;#].*$//;
            $v =~ s/^\s+|\s+$//g;
            if ( lc($k) eq 'jaildefaultshell' ) {
                close $fh;
                return $v =~ /^(1|yes|on|true)$/i ? 1 : 0;
            }
        }
        close $fh;
    }
    return 1;
}

# ---------------------------------------------------------------------------
# Private policy + sshd login evaluation. Sensitive keys
# (normal_shell_users, sshd allow/deny lists) live in the root-only
# $PRIVATE_FILE; the world-readable policy file carries the rest. GET_SHELL
# returns booleans for the caller only, never raw name lists.
# ---------------------------------------------------------------------------

sub _read_private {
    my $merged = _read_policy();
    my $priv = _read_policy($PRIVATE_FILE);
    for my $k (qw(normal_shell_users sshd_allowusers sshd_allowgroups sshd_denyusers sshd_denygroups)) {
        $merged->{$k} = $priv->{$k} if defined $priv->{$k};
    }
    return $merged;
}

sub _caller_group_names {
    my ($user) = @_;
    # Groups of $user from the primary gid plus /etc/group membership.
    # Pure system files; no user paths involved. $GROUP_FILE is overridable
    # for tests.
    my %names;
    my @pw = getpwnam($user);
    if (@pw) {
        my $primary = ( getgrgid( $pw[3] ) )[0];
        $names{$primary} = 1 if defined $primary;
    }
    if ( open my $fh, '<', $GROUP_FILE ) {
        while ( my $line = <$fh> ) {
            chomp $line;
            my ( $gname, undef, undef, $members ) = split /:/, $line, 4;
            next unless defined $gname && defined $members;
            my %has = map { $_ => 1 } split /,/, $members;
            $names{$gname} = 1 if $has{$user};
        }
        close $fh;
    }
    return keys %names;
}

sub _sshd_pattern_match {
    my ( $pattern, $name ) = @_;
    # sshd pattern syntax: * and ? wildcards; user@host matches on the user
    # part (any host). Returns 1 on match.
    my ($left) = split /@/, $pattern, 2;
    my $re = quotemeta($left);
    $re =~ s/\\\*/.*/g;
    $re =~ s/\\\?/./g;
    return $name =~ /^$re$/ ? 1 : 0;
}

sub _sshd_list_match {
    my ( $list_text, $name, $groups_ar ) = @_;
    # Returns ( $positive_hit, $negated_hit ). A leading ! negates; a
    # negated hit vetoes (sshd first-match-wins, approximated).
    my ( $pos, $neg ) = ( 0, 0 );
    my @names = ref $groups_ar eq 'ARRAY' ? @{$groups_ar} : ($name);
    for my $raw ( split /[\s,]+/, $list_text // '' ) {
        next if $raw eq '';
        my $negated = $raw =~ s/^!//;
        for my $n (@names) {
            if ( _sshd_pattern_match( $raw, $n ) ) {
                if ($negated) { $neg = 1; }
                else          { $pos = 1; }
            }
        }
    }
    return ( $pos, $neg );
}

sub _login_blocked {
    my ( $policy, $user ) = @_;
    # Returns ( blocked_bool, reason ). Deny lists win over allow lists;
    # within a list a negated match vetoes. Approximate sshd semantics,
    # documented as such; fail-open nothing (unknown => not blocked).
    my @groups = _caller_group_names($user);
    my ( $dpos, $dneg ) = _sshd_list_match( $policy->{sshd_denyusers}, $user );
    if ( $dpos && !$dneg ) {
        return ( 1, 'denyusers' );
    }
    my $allow = $policy->{sshd_allowusers};
    if ( defined $allow && $allow =~ /\S/ ) {
        my ( $apos, $aneg ) = _sshd_list_match( $allow, $user );
        if ( $aneg || !$apos ) {
            return ( 1, 'allowusers' );
        }
    }
    my ( $gdpos, $gdneg ) = _sshd_list_match( $policy->{sshd_denygroups}, $user, \@groups );
    if ( $gdpos && !$gdneg ) {
        return ( 1, 'denygroups' );
    }
    my $gallow = $policy->{sshd_allowgroups};
    if ( defined $gallow && $gallow =~ /\S/ ) {
        my ( $gapos, $ganeg ) = _sshd_list_match( $gallow, $user, \@groups );
        if ( $ganeg || !$gapos ) {
            return ( 1, 'allowgroups' );
        }
    }
    return ( 0, '' );
}

sub _rate_check_and_record {
    my ( $dir, $user, $now ) = @_;
    # Single implementation in Base; the limit seam stays here.
    local $Cpanel::Admin::Modules::UserTools::Base::MAX_CHANGES_PER_HOUR = $MAX_CHANGES_PER_HOUR;
    return Cpanel::Admin::Modules::UserTools::Base::_rate_check_and_record( $dir, $user, $now );
}

sub _audit {
    my ( $log, $user, $old, $new ) = @_;
    return Cpanel::Admin::Modules::UserTools::Base::_audit( $log, $user, $old, $new );
}

# Runs whmapi1 modifyacct through the documented `shell` parameter
# (api.docs.cpanel.net WHM modifyacct: HASSHELL plus a shell path).
# Isolated so tests can override it; list form, no shell. The output is
# decoded as JSON and success requires metadata.result == 1 (a regex could
# match the flag text elsewhere in the payload). Failure returns the
# metadata reason, truncated.
sub _whm_modify_shell {
    my ( $user, $hasshell, $shell ) = @_;
    my $whmapi1 = $WHMAPI1;
    my @cmd = ( $whmapi1, '--output=json', 'modifyacct', "user=$user", "HASSHELL=$hasshell", "shell=$shell" );
    open my $fh, '-|', @cmd or return ( 0, "cannot run whmapi1: $!" );
    local $/;
    my $out = <$fh>;
    close $fh;
    if ( $? != 0 || !defined $out ) {
        return ( 0, 'modifyacct did not run cleanly' );
    }
    require JSON::PP;
    my $data = eval { JSON::PP->new()->decode($out) };
    if ( $@ || ref $data ne 'HASH' || ref $data->{metadata} ne 'HASH' ) {
        return ( 0, 'modifyacct returned an unreadable reply' );
    }
    if ( ( $data->{metadata}{result} // 0 ) != 1 ) {
        my $reason = substr( $data->{metadata}{reason} // 'unknown error', 0, 200 );
        return ( 0, $reason );
    }
    return ( 1, '' );
}

# ---------------------------------------------------------------------------
# GET_SHELL: read-only state for the caller.
# ---------------------------------------------------------------------------

sub GET_SHELL {
    my ($self) = @_;

    my ( $user, $gate_err ) = _gate_privileged( $self, 'usertools_shell' );
    if ( !defined $user ) {
        return { error => $gate_err };
    }
    my @pw = getpwnam($user);
    if ( !@pw ) {
        return { error => 'unknown account' };
    }
    my ( $uid, $shell ) = @pw[ 2, 8 ];
    my $policy = _read_private();
    my @allowed = _csv_list( $policy->{allowed_shell_modes} );
    @allowed = qw(disabled jailed) unless @allowed;
    my $jailshell_on = _jaildefaultshell_on();
    if ( !$jailshell_on ) {
        @allowed = grep { $_ ne 'jailed' } @allowed;
    }
    my %normal_users = map { $_ => 1 } _csv_list( $policy->{normal_shell_users} );
    my ( $blocked, $reason ) = _login_blocked( $policy, $user );
    return {
        mode               => _shell_to_mode($shell),
        shell_path         => defined $shell ? $shell : '',
        allowed_modes      => \@allowed,
        normal_allowed     => $normal_users{$user} ? 1 : 0,
        jailed_available   => $jailshell_on ? 1 : 0,
        ssh_port           => $policy->{ssh_port} // '',
        ssh_login_blocked  => { blocked => $blocked, reason => $reason },
    };
}

# ---------------------------------------------------------------------------
# SET_SHELL {mode}: change the caller's shell. Rejects anything but mode.
# ---------------------------------------------------------------------------

sub SET_SHELL {
    my ( $self, @args ) = @_;

    my ( $user, $gate_err ) = _gate_privileged( $self, 'usertools_shell' );
    if ( !defined $user ) {
        return { error => $gate_err };
    }
    if ( @args != 1 || ref $args[0] ne 'HASH' ) {
        return { error => 'mode is required' };
    }
    my @keys = sort keys %{ $args[0] };
    if ( @keys != 1 || $keys[0] ne 'mode' ) {
        return { error => 'only the mode key is accepted' };
    }
    my $mode = $args[0]{mode};
    if ( !defined $mode ) {
        return { error => 'mode is required' };
    }

    my $policy = _read_private();
    my @allowed = _csv_list( $policy->{allowed_shell_modes} );
    @allowed = qw(disabled jailed) unless @allowed;
    my %allowed = map { $_ => 1 } @allowed;
    if ( !$allowed{$mode} ) {
        return { error => 'mode is not allowed by policy' };
    }
    my %normal_users = map { $_ => 1 } _csv_list( $policy->{normal_shell_users} );
    if ( $mode eq 'normal' && !$normal_users{$user} ) {
        return { error => 'normal shell is not allowed for this account' };
    }
    if ( $mode eq 'jailed' && !_jaildefaultshell_on() ) {
        return {
            error => 'Jailed shell requires "Use cPanel jailshell by default" (jaildefaultshell=1) in WHM Tweak Settings; ask your host'
        };
    }

    my $acc_err = do {
        local $Cpanel::Admin::Modules::UserTools::Base::USERDATA_DIR = $USERDATA_DIR;
        local $Cpanel::Admin::Modules::UserTools::Base::SUSPEND_DIR  = $SUSPEND_DIR;
        Cpanel::Admin::Modules::UserTools::Base::_gate_account($user);
    };
    if ( defined $acc_err ) {
        return { error => $acc_err };
    }
    my @pw = getpwnam($user);

    my ( $hasshell, $shell ) = _mode_to_shell($mode);
    if ( !defined $hasshell ) {
        return { error => 'unknown mode' };
    }
    # Already in the requested mode is a no-op — no WHM call, no audit
    # line, no rate-limit slot (mirrors SET_APP_DOCROOT's no-op: the getpwnam
    # read costs nothing, so checking before the rate record keeps
    # "disabled->disabled" and friends out of the 10-per-hour budget).
    my $old_shell = $pw[8] // SHELL_NOSHELL;
    my $old_mode  = _shell_to_mode($old_shell);
    if ( $old_mode eq $mode ) {
        return { mode => $mode, shell_path => $shell, changed => 0 };
    }
    if ( !_rate_check_and_record( $RATELIMIT_DIR, $user ) ) {
        return { error => 'rate limit: at most 10 shell changes per hour' };
    }
    my ( $ok, $err ) = _whm_modify_shell( $user, $hasshell, $shell );
    if ( !$ok ) {
        return { error => "shell change failed: $err" };
    }
    my @fresh = getpwnam($user);
    my $fresh_shell = @fresh ? $fresh[8] : undef;
    if ( !defined $fresh_shell || $fresh_shell ne $shell ) {
        # Fail-closed: on cPanel 11.138 modifyacct ignores `shell=` and
        # applies the server default shell. Never leave an unrequested or
        # policy-disallowed shell in place: immediately restore the previous
        # shell (or noshell if the previous was not a standard mode), and
        # audit both the mismatch attempt and the rollback.
        my $got_mode = _shell_to_mode($fresh_shell);
        _audit( $AUDIT_LOG, $user, $old_mode, "mismatch:$mode(got:$got_mode)" );
        my ( $rb_has, $rb_shell ) = _mode_to_shell($old_mode);
        if ( !defined $rb_has ) {
            ( $rb_has, $rb_shell ) = ( 0, SHELL_NOSHELL );
        }
        _whm_modify_shell( $user, $rb_has, $rb_shell );
        my @after = getpwnam($user);
        my $after_shell = @after ? $after[8] : undef;
        my $rb_mode = _shell_to_mode($after_shell);
        _audit( $AUDIT_LOG, $user, "rollback:$got_mode", $rb_mode );
        return { error => 'shell change did not take effect; previous shell restored; contact your host' };
    }
    _audit( $AUDIT_LOG, $user, $old_mode, $mode );
    return { mode => $mode, shell_path => $shell };
}

1;
