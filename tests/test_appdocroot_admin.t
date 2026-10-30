# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for admin/Cpanel/Admin/Modules/UserTools/AppDocroot.pm
#, runnable WITHOUT a cPanel server:
#   prove -Itests/lib -Iadmin tests/test_appdocroot_admin.t
#
# Technique: same as test_shell_admin.t — stub Cpanel::Admin::Base, drive
# SET_APP_DOCROOT with a blessed fake (caller name via package var), mock
# getpwnam (uid/home) and the WHM/uapi spawns (fixture binaries programmed
# through the environment). Policy, rate-limit, audit, suspend and userdata
# locations are package vars pointed at a File::Temp tree. Every gate and
# refusal path is covered.
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
our ( %FAKE_PW, $FEATURE_OK );
$FEATURE_OK = 1;

BEGIN {
    *CORE::GLOBAL::getpwnam = sub {
        my ($name) = @_;
        if ( exists $FAKE_PW{$name} ) {
            return @{ $FAKE_PW{$name} };
        }
        return CORE::getpwnam($name);
    };
}

require "$FindBin::Bin/../admin/Cpanel/Admin/Modules/UserTools/AppDocroot.pm";

*Cpanel::Admin::Modules::UserTools::AppDocroot::get_caller_username = sub { $FakeUser };
*Cpanel::Admin::Modules::UserTools::AppDocroot::cpuser_has_feature_or_die = sub {
    my ( $self, $feature ) = @_;
    die "feature denied\n" unless $FEATURE_OK;
    return 1;
};

sub make_self {
    return bless {}, 'Cpanel::Admin::Modules::UserTools::AppDocroot';
}

sub make_dirs {
    my $root = tempdir( CLEANUP => 1 );
    make_path("$root/ratelimit");
    make_path("$root/suspend");
    make_path("$root/users");
    open my $fh, '>', "$root/policy.conf" or die $!;
    print $fh "enable_app_helper=1\nallow_user_app_docroot=1\n";
    close $fh;
    # Plain assignment (not local): each test block calls make_dirs() first,
    # so the locations always point at the current block's tree.
    $Cpanel::Admin::Modules::UserTools::AppDocroot::RATELIMIT_DIR = "$root/ratelimit";
    $Cpanel::Admin::Modules::UserTools::AppDocroot::AUDIT_LOG     = "$root/audit.log";
    $Cpanel::Admin::Modules::UserTools::AppDocroot::WHMAPI1       = "$root/bin/whmapi1";
    $Cpanel::Admin::Modules::UserTools::AppDocroot::UAPI          = "$root/bin/uapi";
    $Cpanel::Admin::Modules::UserTools::AppDocroot::POLICY_FILE   = "$root/policy.conf";
    $Cpanel::Admin::Modules::UserTools::AppDocroot::USERDATA_DIR  = "$root/users";
    $Cpanel::Admin::Modules::UserTools::AppDocroot::SUSPEND_DIR   = "$root/suspend";
    $FEATURE_OK = 1;
    %FAKE_PW    = ();
    return $root;
}

sub set_user {
    my ( $name, $uid ) = @_;
    $FakeUser = $name;
    $FAKE_PW{$name} = [ $name, 'x', $uid, $uid, '', '', '', "/home/$name", '/bin/bash' ];
    return;
}

sub write_bins {
    my ($root) = @_;
    make_path("$root/bin");
    open my $wh, '>', "$root/bin/whmapi1" or die $!;
    print $wh <<'SCRIPT';
#!/bin/bash
# Fixture: records argv, then behaves per FAKE_WHM_MODE. On success it
# records the new docroot in FAKE_DOCROOT_FILE (as $FAKE_DOCROOT_HOME/<doc>)
# so the follow-up read API sees the change, like the real server.
printf '%s\n' "$@" >"$FAKE_WHM_ARGV"
mode="$FAKE_WHM_MODE"
case "$mode" in
  ok)
    dr=""
    for a in "$@"; do case "$a" in docroot=*) dr="${a#docroot=}";; esac; done
    if [ -n "$FAKE_DOCROOT_FILE" ] && [ -n "$FAKE_DOCROOT_HOME" ] && [ -n "$dr" ]; then
      printf '%s/%s\n' "$FAKE_DOCROOT_HOME" "$dr" >"$FAKE_DOCROOT_FILE"
    fi
    printf '{"metadata":{"result":1}}\n'; exit 0;;
  fail)
    printf '{"metadata":{"result":0,"reason":"no such account"}}\n'; exit 0;;
  garbage)
    printf 'not json at all\n'; exit 0;;
esac
printf '{"metadata":{"result":0,"reason":"bad mode"}}'; exit 0
SCRIPT
    close $wh;
    chmod 0755, "$root/bin/whmapi1";
    open my $uh, '>', "$root/bin/uapi" or die $!;
    print $uh <<'SCRIPT';
#!/bin/bash
# Fixture: DomainInfo read API (real cPanel 11.138 shape: result.data with
# main_domain as a HASH, plus addon_domains, parked_domains, sub_domains).
# The current docroot comes from the FAKE_DOCROOT_FILE state when it holds
# a value (a successful whmapi1 wrote it), else FAKE_DOMAININFO_DOCROOT.
printf '%s\n' "$@" >"$FAKE_UAPI_ARGV"
docroot="$FAKE_DOMAININFO_DOCROOT"
if [ -n "$FAKE_DOCROOT_FILE" ] && [ -s "$FAKE_DOCROOT_FILE" ]; then
  docroot="$(cat "$FAKE_DOCROOT_FILE")"
fi
cat <<JSON
{"apiversion":3,"func":"domains_data","module":"DomainInfo","result":{"data":{"addon_domains":[],"main_domain":{"customlog":[{"format":"combined","target":"/etc/apache2/logs/domlogs/example.com"}],"documentroot":"$docroot","domain":"example.com","group":"uttest","hascgi":1,"homedir":"/home/uttest","ip":"192.0.2.10","is_temporary":0,"owner":"root","phpopenbasedirprotect":1,"port":"80","scriptalias":[{"path":"/home/uttest/public_html/cgi-bin","url":"/cgi-bin/"}],"serveradmin":"webmaster@example.com","serveralias":"mail.example.com www.example.com","servername":"example.com","status":"","type":"main_domain","usecanonicalname":"Off","user":"uttest"},"parked_domains":[],"sub_domains":[]},"errors":null,"messages":null,"metadata":{"transformed":1},"status":1,"warnings":null}}
JSON
exit 0
SCRIPT
    close $uh;
    chmod 0755, "$root/bin/uapi";
    return;
}

# --- _actions allowlist ----------------------------------------------------------
{
    my @actions = Cpanel::Admin::Modules::UserTools::AppDocroot->_actions();
    is_deeply( \@actions, ['SET_APP_DOCROOT'], 'exactly one function' );
}

# --- happy paths (real changes; no-ops live in their own block) ---------------
{
    my $root = make_dirs();
    set_user( 'uttest', 1000 );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    write_bins($root);
    local $ENV{FAKE_WHM_ARGV} = "$root/whm-argv.txt";
    local $ENV{FAKE_WHM_MODE} = 'ok';
    local $ENV{FAKE_UAPI_ARGV} = "$root/uapi-argv.txt";
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html';
    local $ENV{FAKE_DOCROOT_FILE} = "$root/docroot.txt";
    local $ENV{FAKE_DOCROOT_HOME} = '/home/uttest';

    my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is_deeply( $got, { enable => 1, docroot => 'public_html/public', changed => 1 },
        'enable=1 sets app docroot' );
    open my $afh, '<', "$root/whm-argv.txt" or die $!;
    my @argv = map { chomp; $_ } <$afh>;
    close $afh;
    ok( ( grep { $_ eq 'username=uttest' } @argv ) ? 1 : 0, 'caller username passed, never a request user' );
    ok( ( grep { $_ eq 'docroot=public_html/public' } @argv ) ? 1 : 0, 'hard-coded app docroot passed' );
    ok( !( grep { $_ =~ /^user=/ } @argv ), 'no user= smuggling possible' );
    open my $ufh, '<', "$root/uapi-argv.txt" or die $!;
    my $uargv = do { local $/; <$ufh> };
    close $ufh;
    like( $uargv, qr/DomainInfo/, 'new docroot verified through the read API' );
    open my $lfh, '<', "$root/audit.log" or die "no audit log: $!";
    my $line = <$lfh>;
    close $lfh;
    like( $line, qr/uttest primary-docroot:.*->primary-docroot:public_html\/public/, 'audit line written' );
    is( ( stat("$root/audit.log") )[2] & 07777, 0600, 'audit log is 0600' );

    # The state file now holds public_html/public, so enable=0 is a real
    # change back.
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 0 } );
    is_deeply( $got, { enable => 0, docroot => 'public_html', changed => 1 },
        'enable=0 restores plain docroot' );
}

# --- No-op when already serving from the target ------------------------------
{
    my $root = make_dirs();
    set_user( 'uttest', 1000 );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    write_bins($root);
    local $ENV{FAKE_WHM_ARGV} = "$root/whm-argv.txt";
    local $ENV{FAKE_WHM_MODE} = 'ok';
    local $ENV{FAKE_UAPI_ARGV} = "$root/uapi-argv.txt";
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html/public';
    local $ENV{FAKE_DOCROOT_FILE} = "$root/docroot.txt";
    local $ENV{FAKE_DOCROOT_HOME} = '/home/uttest';

    my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is_deeply( $got, { enable => 1, docroot => 'public_html/public', changed => 0 },
        'enable=1 while already on public_html/public is a no-op' );
    ok( !-e "$root/whm-argv.txt", 'no WHM call for the no-op' );
    ok( !-e "$root/audit.log",   'no audit line for the no-op' );
    ok( !-e "$root/ratelimit/uttest", 'no rate-limit slot consumed' );

    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html';
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 0 } );
    is_deeply( $got, { enable => 0, docroot => 'public_html', changed => 0 },
        'enable=0 while already on public_html is a no-op' );
    ok( !-e "$root/whm-argv.txt", 'still no WHM call' );
    ok( !-e "$root/audit.log",   'still no audit line' );
    ok( !-e "$root/ratelimit/uttest", 'still no rate-limit slot consumed' );
}

# --- gates: feature + both policy keys, before anything else ---------------------
{
    my $root = make_dirs();
    set_user( 'uttest', 1000 );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    write_bins($root);
    local $ENV{FAKE_WHM_MODE} = 'ok';
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html/public';

    local $FEATURE_OK = 0;
    my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'This feature is not enabled for your account.', 'refused without feature' );
    ok( !-e "$root/ratelimit/uttest", 'refusals do not consume rate limit' );

    local $FEATURE_OK = 1;
    open my $pfh, '>', "$root/policy.conf" or die $!;
    print $pfh "enable_app_helper=0\nallow_user_app_docroot=1\n";
    close $pfh;
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'App Helper is disabled by server policy.', 'refused when helper disabled' );

    open my $qfh, '>', "$root/policy.conf" or die $!;
    print $qfh "enable_app_helper=1\nallow_user_app_docroot=0\n";
    close $qfh;
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    like( $got->{error}, qr/disabled by server policy/, 'refused when user docroot not allowed' );
    like( $got->{error}, qr/whmapi1 set_primary_domain_docroot username=uttest docroot=public_html\/public/,
        'refusal carries the copy-ready host command' );
    ok( !-e "$root/ratelimit/uttest", 'policy refusals do not consume rate limit' );

    open my $rfh, '>', "$root/policy.conf" or die $!;
    print $rfh "enable_app_helper=1\n";
    close $rfh;
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    like( $got->{error}, qr/disabled by server policy/, 'missing allow key means off' );
}

# --- argument shape: exactly one boolean key -------------------------------------
{
    my $root = make_dirs();
    set_user( 'uttest', 1000 );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    write_bins($root);
    local $ENV{FAKE_WHM_MODE} = 'ok';
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html/public';

    my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1, user => 'victim' } );
    is( $got->{error}, 'only the enable key is accepted', 'user= smuggling refused' );

    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1, username => 'victim' } );
    is( $got->{error}, 'only the enable key is accepted', 'username= smuggling refused' );

    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { mode => 1 } );
    is( $got->{error}, 'only the enable key is accepted', 'wrong key refused' );

    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT( make_self(), '1' );
    is( $got->{error}, 'enable is required', 'non-hash args refused' );

    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT( make_self() );
    is( $got->{error}, 'enable is required', 'missing args refused' );

    for my $bad ( 2, 'yes', '', {}, [] ) {
        $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
            make_self(), { enable => $bad } );
        is( $got->{error}, 'enable must be a boolean', 'non-boolean refused' );
    }
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => undef } );
    is( $got->{error}, 'enable must be a boolean', 'undef refused' );
}

# --- account checks + rate limit ---------------------------------------------------
{
    my $root = make_dirs();
    write_bins($root);
    local $ENV{FAKE_WHM_MODE} = 'ok';
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html/public';

    set_user( 'root', 0 );
    my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'refusing change for a root/system account', 'root refused' );

    set_user( 'svc', 500 );
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'refusing change for a root/system account', 'system uid refused' );

    set_user( 'ghost', 1000 );
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'not a cPanel account', 'non-account refused' );

    set_user( 'uttest', 1000 );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    open my $sfh, '>', "$root/suspend/uttest" or die $!;
    close $sfh;
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'refusing change for a suspended account', 'suspended refused' );
    unlink "$root/suspend/uttest";

    # Pre-fill 5 changes this hour; the current docroot is plain
    # public_html, so enable=1 is a REAL change and the 6th is refused.
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html';
    open my $rfh, '>', "$root/ratelimit/uttest" or die $!;
    my $now = time();
    print $rfh join( "\n", map { $now - $_ * 60 } 0 .. 4 ) . "\n";
    close $rfh;
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'rate limit: at most 5 primary-domain docroot changes per hour',
        'rate limit enforced' );
}

# --- The 6th REAL change in an hour is refused; no-ops never count -------------
{
    my $root = make_dirs();
    set_user( 'uttest', 1000 );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    write_bins($root);
    local $ENV{FAKE_WHM_ARGV} = "$root/whm-argv.txt";
    local $ENV{FAKE_WHM_MODE} = 'ok';
    local $ENV{FAKE_UAPI_ARGV} = "$root/uapi-argv.txt";
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html';
    local $ENV{FAKE_DOCROOT_FILE} = "$root/docroot.txt";
    local $ENV{FAKE_DOCROOT_HOME} = '/home/uttest';

    for my $i ( 1 .. 5 ) {
        my $on = $i % 2 ? 1 : 0;    # alternate direction: always a real change
        my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
            make_self(), { enable => $on } );
        is( $got->{changed}, 1, "real change $i recorded" );
    }
    my @lines = do {
        open my $rfh, '<', "$root/ratelimit/uttest" or die $!;
        <$rfh>;
    };
    is( scalar @lines, 5, 'five rate-limit slots used' );

    # No-ops in between never consume a slot nor hit the limit.
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html/public';
    my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is_deeply( $got, { enable => 1, docroot => 'public_html/public', changed => 0 },
        'no-op stays allowed even when the limit is full' );
    @lines = do {
        open my $rfh, '<', "$root/ratelimit/uttest" or die $!;
        <$rfh>;
    };
    is( scalar @lines, 5, 'the no-op consumed no slot' );

    # The 6th REAL change is refused. The state file (not the env default)
    # holds the live value now: public_html/public, so enable=0 is the real
    # change direction.
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 0 } );
    is( $got->{error}, 'rate limit: at most 5 primary-domain docroot changes per hour',
        '6th real change in an hour refused' );
}

# --- WHM failure + verification ----------------------------------------------------
{
    my $root = make_dirs();
    set_user( 'uttest', 1000 );
    open my $fh, '>', "$root/users/uttest" or die $!;
    close $fh;
    write_bins($root);

    local $ENV{FAKE_WHM_ARGV} = "$root/whm-argv.txt";
    local $ENV{FAKE_UAPI_ARGV} = "$root/uapi-argv.txt";
    local $ENV{FAKE_WHM_MODE} = 'fail';
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html';
    my $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'docroot change failed: no such account', 'WHM reason passed through' );

    local $ENV{FAKE_WHM_MODE} = 'garbage';
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    like( $got->{error}, qr/unreadable reply/, 'non-JSON WHM reply refused' );

    local $ENV{FAKE_WHM_MODE} = 'ok';
    local $ENV{FAKE_DOMAININFO_DOCROOT} = '/home/uttest/public_html';
    $got = Cpanel::Admin::Modules::UserTools::AppDocroot::SET_APP_DOCROOT(
        make_self(), { enable => 1 } );
    is( $got->{error}, 'docroot change did not take effect; contact your host',
        'stale docroot honestly reported' );
}

done_testing();
