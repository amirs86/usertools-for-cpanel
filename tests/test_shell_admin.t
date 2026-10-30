# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for admin/Cpanel/Admin/Modules/UserTools/Shell.pm,
# runnable WITHOUT a cPanel server:  prove -Itests/lib tests/test_shell_admin.t
#
# Technique: stub Cpanel::Admin::Base, drive GET_SHELL/SET_SHELL with a
# blessed fake (caller name via package var), mock getpwnam (uid/shell) and
# _whm_modify_shell (records argv, programmable outcome). Policy,
# rate-limit, audit, suspend and userdata locations are package vars pointed
# at a File::Temp tree. Every refusal path is covered.
use strict;
use warnings;
no warnings 'once';
use Test::More;
use FindBin;
use File::Temp qw(tempdir);
use File::Path qw(make_path);

use lib "$FindBin::Bin/lib";
use lib "$FindBin::Bin/../admin";

our $FakeUser = 'uttest';
our ( %FAKE_PW, @WHM_CALLS, $WHM_OK, $FEATURE_OK, $APPLIED_SHELL );
$FEATURE_OK = 1;

BEGIN {
    *CORE::GLOBAL::getpwnam = sub {
        my ($name) = @_;
        if ( exists $FAKE_PW{$name} ) {
            my @r = @{ $FAKE_PW{$name} };
            $r[8] = $APPLIED_SHELL if defined $APPLIED_SHELL;
            return @r;
        }
        return CORE::getpwnam($name);
    };
}

require "$FindBin::Bin/../admin/Cpanel/Admin/Modules/UserTools/Shell.pm";

*Cpanel::Admin::Modules::UserTools::Shell::get_caller_username = sub { $FakeUser };
*Cpanel::Admin::Modules::UserTools::Shell::cpuser_has_feature_or_die = sub {
    my ( $self, $feature ) = @_;
    die "feature denied\n" unless $FEATURE_OK;
    return 1;
};

sub make_self {
    return bless {}, 'Cpanel::Admin::Modules::UserTools::Shell';
}

sub make_dirs {
    my $root = tempdir( CLEANUP => 1 );
    make_path("$root/ratelimit");
    make_path("$root/suspend");
    make_path("$root/users");
    open my $fh, '>', "$root/policy.conf" or die $!;
    print $fh "enable_shell=1\nallowed_shell_modes=disabled,jailed\nssh_port=2222\n";
    close $fh;
    open my $pfh, '>', "$root/private.conf" or die $!;
    print $pfh "normal_shell_users=\n";
    close $pfh;
    open my $gfh, '>', "$root/groups.conf" or die $!;
    print $gfh "uttest:x:1000:\nmail:x:12:\n";
    close $gfh;
    # Plain assignment (not local): each test block calls make_dirs() first,
    # so the locations always point at the current block's tree.
    $Cpanel::Admin::Modules::UserTools::Shell::POLICY_FILE   = "$root/policy.conf";
    $Cpanel::Admin::Modules::UserTools::Shell::PRIVATE_FILE  = "$root/private.conf";
    $Cpanel::Admin::Modules::UserTools::Shell::GROUP_FILE    = "$root/groups.conf";
    $Cpanel::Admin::Modules::UserTools::Shell::RATELIMIT_DIR = "$root/ratelimit";
    $Cpanel::Admin::Modules::UserTools::Shell::AUDIT_LOG     = "$root/audit.log";
    $Cpanel::Admin::Modules::UserTools::Shell::SUSPEND_DIR   = "$root/suspend";
    $Cpanel::Admin::Modules::UserTools::Shell::USERDATA_DIR  = "$root/users";
    $Cpanel::Admin::Modules::UserTools::Shell::CPANEL_CONFIG = "$root/cpanel.config";
    $FEATURE_OK     = 1;
    $APPLIED_SHELL  = undef;
    %FAKE_PW        = ();
    return $root;
}

sub set_user {
    my ( $name, $uid, $shell ) = @_;
    $FakeUser = $name;
    $FAKE_PW{$name} = [ $name, 'x', $uid, $uid, '', '', '', "/home/$name", $shell ];
    return;
}

# --- _actions allowlist ----------------------------------------------------------
{
    my @actions = Cpanel::Admin::Modules::UserTools::Shell->_actions();
    is_deeply( [ sort @actions ], [qw(GET_SHELL SET_SHELL)], 'exactly two functions' );
}

# --- GET_SHELL mapping ----------------------------------------------------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/jailshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    my $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $got->{mode},          'jailed', 'jailshell maps to jailed' );
    is( $got->{normal_allowed}, 0,       'normal not allowed by default' );
    is( $got->{ssh_port},       '2222',  'ssh port from policy' );
    is_deeply( $got->{allowed_modes}, [qw(disabled jailed)], 'allowed modes from policy' );

    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $got->{mode}, 'disabled', 'noshell maps to disabled' );

    set_user( 'uttest', 1000, '/bin/bash' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $got->{mode},           'normal', 'existing bash reads as normal' );
    is( $got->{normal_allowed}, 0,        'host-set bash flagged by policy' );

    set_user( 'uttest', 1000, '/bin/false' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $got->{mode}, 'other', 'unknown shells read as other' );
}

# --- SET_SHELL happy path ----------------------------------------------------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    @WHM_CALLS = ();
    $WHM_OK = 1;
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    no warnings 'redefine';
    local *Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell = sub {
        my ( $user, $hasshell, $shell ) = @_;
        push @WHM_CALLS, [$user, $hasshell, $shell];
        $APPLIED_SHELL = $shell;    # the mock "applies" it for the re-read
        return ( 1, '' );
    };
    my $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{mode}, 'jailed', 'mode set' );
    is_deeply( \@WHM_CALLS, [['uttest', 1, '/usr/local/cpanel/bin/jailshell']],
        'explicit jailshell path passed (never the default)' );
    open my $afh, '<', "$root/audit.log" or die "no audit log: $!";
    my $line = <$afh>;
    close $afh;
    like( $line, qr/uttest disabled->jailed/, 'audit line written' );
    is( ( stat("$root/audit.log") )[2] & 07777, 0600, 'audit log is 0600' );

    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'disabled' } );
    is_deeply( $WHM_CALLS[-1], ['uttest', 0, '/usr/local/cpanel/bin/noshell'],
        'disabled maps to noshell explicitly' );
}

# --- L2b: same-shell change is a no-op (no WHM call, no audit, no rate slot) ---------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    @WHM_CALLS = ();
    $WHM_OK = 1;
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    no warnings 'redefine';
    local *Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell = sub {
        push @WHM_CALLS, [@_];
        $APPLIED_SHELL = $_[2];
        return ( 1, '' );
    };
    my $got;

    for my $i ( 1 .. 10 ) {
        $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'disabled' } );
        is_deeply( $got, { mode => 'disabled', shell_path => '/usr/local/cpanel/bin/noshell', changed => 0 },
            "same-mode no-op $i returns changed:0" );
    }
    is( scalar(@WHM_CALLS), 0, 'no WHM call from ten same-mode changes' );
    ok( !-e "$root/audit.log", 'no audit line from same-mode changes' );
    ok( !-e "$root/ratelimit/uttest", 'no rate slot consumed by same-mode changes' );

    # The 11th REAL change is still refused (no-ops bypass the limit,
    # real changes do not).
    open my $rfh, '>', "$root/ratelimit/uttest" or die $!;
    my $now = time();
    print $rfh join( "\n", map { $now - $_ * 60 } 0 .. 9 ) . "\n";
    close $rfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'rate limit: at most 10 shell changes per hour', '11th real change still refused' );
    is( scalar(@WHM_CALLS), 0, 'refused change made no WHM call' );

    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'disabled' } );
    is_deeply( $got, { mode => 'disabled', shell_path => '/usr/local/cpanel/bin/noshell', changed => 0 },
        'same-mode still permitted while the rate store is full' );
}

# --- SET_SHELL refusals -----------------------------------------------------------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    no warnings 'redefine';
    local *Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell = sub { return ( 1, '' ); };

    my $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL(
        make_self(), { mode => 'jailed', user => 'root' } );
    is( $got->{error}, 'only the mode key is accepted', 'user= smuggling refused' );

    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL(
        make_self(), { mode => 'jailed', username => 'victim' } );
    is( $got->{error}, 'only the mode key is accepted', 'username= smuggling refused' );

    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'turbo' } );
    is( $got->{error}, 'mode is not allowed by policy', 'bad mode refused' );

    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), 'jailed' );
    is( $got->{error}, 'mode is required', 'non-hash args refused' );

    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'normal' } );
    is( $got->{error}, 'mode is not allowed by policy', 'unlisted mode refused' );

    open my $pfh, '>', "$root/policy.conf" or die $!;
    print $pfh "enable_shell=1\nallowed_shell_modes=disabled,jailed,normal\n";
    close $pfh;
    open my $qfh, '>', "$root/private.conf" or die $!;
    print $qfh "normal_shell_users=\n";
    close $qfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'normal' } );
    is( $got->{error}, 'normal shell is not allowed for this account', 'normal gated by policy list' );

    set_user( 'root', 0, '/bin/bash' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'refusing change for a root/system account', 'root refused' );

    set_user( 'svc', 500, '/usr/local/cpanel/bin/noshell' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'refusing change for a root/system account', 'system uid refused' );

    set_user( 'ghost', 1000, '/usr/local/cpanel/bin/noshell' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'not a cPanel account', 'non-account refused' );

    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    open my $sfh, '>', "$root/suspend/uttest" or die $!;
    close $sfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'refusing change for a suspended account', 'suspended refused' );
    unlink "$root/suspend/uttest";
}

# --- normal allowed via policy list + rate limit ------------------------------------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    open my $fh, '>', "$root/policy.conf" or die $!;
    print $fh "enable_shell=1\nallowed_shell_modes=disabled,jailed,normal\n";
    close $fh;
    open my $nh, '>', "$root/private.conf" or die $!;
    print $nh "normal_shell_users=uttest\n";
    close $nh;
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/jailshell' );
    open my $ufh, '>', "$root/users/uttest" or die $!;
    close $ufh;
    no warnings 'redefine';
    local *Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell = sub {
        push @WHM_CALLS, [@_];
        $APPLIED_SHELL = $_[2];    # the mock "applies" it for the re-read
        return ( 1, '' );
    };
    @WHM_CALLS = ();
    my $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'normal' } );
    is( $got->{mode}, 'normal', 'listed user may take normal' );
    is_deeply( $WHM_CALLS[-1], ['uttest', 1, '/bin/bash'], 'normal maps to bash explicitly' );

    # Pre-fill 10 changes this hour: the 11th is refused.
    open my $rfh, '>', "$root/ratelimit/uttest" or die $!;
    my $now = time();
    print $rfh join( "\n", map { $now - $_ * 60 } 0 .. 9 ) . "\n";
    close $rfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'rate limit: at most 10 shell changes per hour', 'rate limit enforced' );
}

# --- Feature + enable_shell enforced inside the module -------------------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;

    local $FEATURE_OK = 0;
    my $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $got->{error}, 'This feature is not enabled for your account.', 'GET refused without feature' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'This feature is not enabled for your account.', 'SET refused without feature' );
    ok( !-e "$root/ratelimit/uttest", 'refusals do not consume rate limit' );

    local $FEATURE_OK = 1;
    open my $pfh, '>', "$root/policy.conf" or die $!;
    print $pfh "enable_shell=0\nallowed_shell_modes=disabled,jailed\n";
    close $pfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $got->{error}, 'Shell access is disabled by server policy.', 'GET refused when disabled' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'Shell access is disabled by server policy.', 'SET refused when disabled' );
    ok( !-e "$root/ratelimit/uttest", 'policy refusals do not consume rate limit' );

    open my $qfh, '>', "$root/policy.conf" or die $!;
    print $qfh "allowed_shell_modes=disabled,jailed\n";
    close $qfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'Shell access is disabled by server policy.', 'missing key means disabled' );
}

# --- Login-blocked booleans, never raw name lists ------------------------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/jailshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    open my $pfh, '>', "$root/private.conf" or die $!;
    print $pfh "normal_shell_users=root,admin\nsshd_allowusers=alice bob\n";
    close $pfh;
    my $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    ok( !exists $got->{sshd_allowusers}, 'no raw allowusers disclosed' );
    ok( !exists $got->{sshd_denygroups}, 'no raw denygroups disclosed' );
    is_deeply( $got->{ssh_login_blocked}, { blocked => 1, reason => 'allowusers' },
        'caller missing from allowusers is blocked' );

    open my $qfh, '>', "$root/private.conf" or die $!;
    print $qfh "sshd_denyusers=uttest\n";
    close $qfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is_deeply( $got->{ssh_login_blocked}, { blocked => 1, reason => 'denyusers' },
        'denyusers blocks' );

    open my $rfh, '>', "$root/private.conf" or die $!;
    print $rfh "sshd_allowusers=*\n";
    close $rfh;
    $got = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is_deeply( $got->{ssh_login_blocked}, { blocked => 0, reason => '' },
        'wildcard allowusers passes' );
}

{
    # Pattern unit checks through _login_blocked with a stubbed group file.
    my $root = make_dirs();
    open my $gfh, '>', "$root/groups.conf" or die $!;
    print $gfh "staff:x:2000:uttest\nwheel:x:10:\n";
    close $gfh;
    no warnings 'redefine';
    local *Cpanel::Admin::Modules::UserTools::Shell::_caller_group_names = sub { return ('staff'); };
    my ( $b, $r );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked( {}, 'uttest' );
    is( "$b/$r", '0/', 'empty policy never blocks' );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked(
        { sshd_allowusers => 'ut?est' }, 'uttest' );
    is( "$b/$r", '0/', '? wildcard matches' );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked(
        { sshd_denyusers => '!uttest' }, 'uttest' );
    is( "$b/$r", '0/', 'negated deny does not block' );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked(
        { sshd_allowusers => 'alice !uttest' }, 'uttest' );
    is( "$b/$r", '1/allowusers', 'negation vetoes an allow list' );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked(
        { sshd_allowgroups => 'staff' }, 'uttest' );
    is( "$b/$r", '0/', 'group allow passes' );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked(
        { sshd_denygroups => 'wheel' }, 'uttest' );
    is( "$b/$r", '0/', 'other group deny passes' );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked(
        { sshd_denygroups => 'st*' }, 'uttest' );
    is( "$b/$r", '1/denygroups', 'group wildcard deny blocks' );
    ( $b, $r ) = Cpanel::Admin::Modules::UserTools::Shell::_login_blocked(
        { sshd_allowusers => 'uttest@anywhere' }, 'uttest' );
    is( "$b/$r", '0/', 'user@host matches on the user' );
}

# --- Real _whm_modify_shell against a fixture binary ---------------------------------
sub write_fake_whmapi1 {
    my ($dir) = @_;
    make_path($dir);
    my $bin = "$dir/whmapi1";
    open my $fh, '>', $bin or die $!;
    print $fh <<'SCRIPT';
#!/bin/bash
# Fixture: records argv, then behaves per FAKE_WHM_MODE.
printf '%s\n' "$@" >"$FAKE_WHM_ARGV"
mode="$FAKE_WHM_MODE"
case "$mode" in
  ok)
    for a in "$@"; do
      case "$a" in shell=*) printf '%s\n' "$a" >"$FAKE_WHM_STATE";; esac
    done
    printf '{"metadata":{"result":1}}\n'; exit 0;;
  ok-nostate)
    printf '{"metadata":{"result":1}}\n'; exit 0;;
  default-bash)
    for a in "$@"; do
      case "$a" in
        HASSHELL=1) printf 'shell=/bin/bash\n' >"$FAKE_WHM_STATE";;
        HASSHELL=0) printf 'shell=/usr/local/cpanel/bin/noshell\n' >"$FAKE_WHM_STATE";;
      esac
    done
    printf '{"metadata":{"result":1}}\n'; exit 0;;
  fail)
    printf '{"metadata":{"result":0,"reason":"no such account"}}\n'; exit 0;;
  longreason)
    printf '{"metadata":{"result":0,"reason":"%s"}}\n' "$(printf 'x%.0s' $(seq 300))"; exit 0;;
  garbage)
    printf 'not json at all\n'; exit 0;;
  nonzero)
    printf '{"metadata":{"result":1}}\n'; exit 3;;
esac
printf '{"metadata":{"result":0,"reason":"bad mode"}}'; exit 0
SCRIPT
    close $fh;
    chmod 0755, $bin;
    return $bin;
}

{
    my $root = make_dirs();
    %FAKE_PW = ();
    my $bin = write_fake_whmapi1("$root/bin");
    local $Cpanel::Admin::Modules::UserTools::Shell::WHMAPI1 = $bin;
    local $ENV{FAKE_WHM_ARGV} = "$root/argv.txt";
    local $ENV{FAKE_WHM_STATE} = "$root/state.txt";
    local $ENV{FAKE_WHM_MODE}  = 'ok';

    my ( $ok, $err ) = Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell(
        'uttest', 1, '/usr/local/cpanel/bin/jailshell' );
    ok( $ok, 'JSON result 1 accepted' );
    open my $afh, '<', "$root/argv.txt" or die $!;
    my @argv = map { chomp; $_ } <$afh>;
    close $afh;
    ok( ( grep { $_ eq 'shell=/usr/local/cpanel/bin/jailshell' } @argv ) ? 1 : 0,
        'shell path passed explicitly' );
    ok( ( grep { $_ eq 'HASSHELL=1' } @argv ) ? 1 : 0, 'HASSHELL passed' );

    local $ENV{FAKE_WHM_MODE} = 'fail';
    ( $ok, $err ) = Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell(
        'uttest', 1, '/usr/local/cpanel/bin/jailshell' );
    ok( !$ok && $err eq 'no such account', 'metadata reason returned' );

    local $ENV{FAKE_WHM_MODE} = 'longreason';
    ( $ok, $err ) = Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell(
        'uttest', 1, '/usr/local/cpanel/bin/jailshell' );
    ok( !$ok && length($err) == 200, 'long reason truncated to 200' );

    local $ENV{FAKE_WHM_MODE} = 'garbage';
    ( $ok, $err ) = Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell(
        'uttest', 1, '/usr/local/cpanel/bin/jailshell' );
    ok( !$ok, 'non-JSON reply refused' );

    local $ENV{FAKE_WHM_MODE} = 'nonzero';
    ( $ok, $err ) = Cpanel::Admin::Modules::UserTools::Shell::_whm_modify_shell(
        'uttest', 1, '/usr/local/cpanel/bin/jailshell' );
    ok( !$ok, 'nonzero exit refused despite JSON body' );
}

{
    # End-to-end re-read: getpwnam follows the fixture's state file.
    my $root = make_dirs();
    %FAKE_PW = ();
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    my $bin = write_fake_whmapi1("$root/bin");
    local $Cpanel::Admin::Modules::UserTools::Shell::WHMAPI1 = $bin;
    local $ENV{FAKE_WHM_ARGV} = "$root/argv.txt";
    local $ENV{FAKE_WHM_STATE} = "$root/state.txt";
    local $ENV{FAKE_WHM_MODE}  = 'ok';
    no warnings 'redefine';
    local *CORE::GLOBAL::getpwnam = sub {
        my ($name) = @_;
        return unless exists $FAKE_PW{$name};
        my @r = @{ $FAKE_PW{$name} };
        if ( open my $sfh, '<', "$root/state.txt" ) {
            my $line = <$sfh>;
            close $sfh;
            if ( defined $line && $line =~ /^shell=(.+)$/ ) {
                $r[8] = $1;
            }
        }
        return @r;
    };
    my $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{mode}, 'jailed', 'verified change succeeds' );

    unlink "$root/state.txt";
    local $ENV{FAKE_WHM_MODE} = 'ok-nostate';
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    is( $got->{error}, 'shell change did not take effect; previous shell restored; contact your host',
        'stale shell honestly reported' );
}

# --- Fail-closed rollback when modifyacct ignores shell= ---------------------
{
    my $root = make_dirs();
    %FAKE_PW = ();
    set_user( 'uttest', 1000, '/usr/local/cpanel/bin/noshell' );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    my $bin = write_fake_whmapi1("$root/bin");
    local $Cpanel::Admin::Modules::UserTools::Shell::WHMAPI1 = $bin;
    local $ENV{FAKE_WHM_ARGV}  = "$root/argv.txt";
    local $ENV{FAKE_WHM_STATE} = "$root/state.txt";
    local $ENV{FAKE_WHM_MODE}  = 'default-bash';
    no warnings 'redefine';
    local *CORE::GLOBAL::getpwnam = sub {
        my ($name) = @_;
        return unless exists $FAKE_PW{$name};
        my @r = @{ $FAKE_PW{$name} };
        if ( open my $sfh, '<', "$root/state.txt" ) {
            my $line = <$sfh>;
            close $sfh;
            if ( defined $line && $line =~ /^shell=(.+)$/ ) {
                $r[8] = $1;
            }
        }
        return @r;
    };

    # 1. Fake whmapi1 applies /bin/bash regardless of shell=...jailshell.
    my $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    like( $got->{error}, qr/previous shell restored/, 'mismatch triggers fail-closed error' );
    my @after = getpwnam('uttest');
    is( $after[8], '/usr/local/cpanel/bin/noshell', 'old shell restored; bash never remains' );
    open my $afh, '<', "$root/audit.log" or die $!;
    my @alines = map { chomp; $_ } <$afh>;
    close $afh;
    is( scalar(@alines), 2, 'two audit lines written (attempt + rollback)' );
    like( $alines[0], qr/uttest disabled->mismatch:jailed\(got:normal\)/, 'mismatch attempt audited' );
    like( $alines[1], qr/uttest rollback:normal->disabled/, 'rollback audited' );

    # 2. jaildefaultshell=0 in cpanel.config hides and refuses jailed up front.
    open my $cfh, '>', "$root/cpanel.config" or die $!;
    print $cfh "jaildefaultshell=0\n";
    close $cfh;
    my $st = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $st->{jailed_available}, 0, 'jailed_available=0 when jaildefaultshell=0' );
    is_deeply( $st->{allowed_modes}, ['disabled'], 'jailed filtered out of allowed_modes' );
    $got = Cpanel::Admin::Modules::UserTools::Shell::SET_SHELL( make_self(), { mode => 'jailed' } );
    like( $got->{error}, qr/jaildefaultshell=1/, 'SET_SHELL jailed refused with clear admin message' );

    # 3. jaildefaultshell=1 restores jailed availability.
    open my $cfh2, '>', "$root/cpanel.config" or die $!;
    print $cfh2 "jaildefaultshell=1\n";
    close $cfh2;
    $st = Cpanel::Admin::Modules::UserTools::Shell::GET_SHELL( make_self() );
    is( $st->{jailed_available}, 1, 'jailed_available=1 when jaildefaultshell=1' );
    is_deeply( $st->{allowed_modes}, [qw(disabled jailed)], 'jailed present when jaildefaultshell=1' );
}

done_testing();
