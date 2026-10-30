# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for hooks/lib/UserTools/Hook/AppSetup.pm, runnable
# WITHOUT a cPanel server:  prove -Itests/lib tests/test_hook_app_setup.t
#
# Technique: fixture home, CORE::GLOBAL::getpwnam override, conf/whmapi1/uapi
# fixture binaries, and an inline privilege drop ($DO_AS_USER runs the
# closure directly). The hook's module requires resolve to the repo files,
# required once here by absolute path so the hook's own requires are no-ops.
use strict;
use warnings;
no warnings 'once';
use Test::More;
use FindBin;
use Cwd qw(abs_path);
use File::Temp qw(tempdir);
use File::Path qw(make_path);

use lib "$FindBin::Bin/lib";

our ( %FAKE_PW, @WHM_ARGV );

BEGIN {
    *CORE::GLOBAL::getpwnam = sub {
        my ($name) = @_;
        if ( exists $FAKE_PW{$name} ) {
            return @{ $FAKE_PW{$name} };
        }
        return CORE::getpwnam($name);
    };
}

my $UTS_PM  = abs_path("$FindBin::Bin/../Cpanel/API/UserTools.pm");
my $BASE_PM = abs_path("$FindBin::Bin/../admin/Cpanel/Admin/Modules/UserTools/Base.pm");
require $UTS_PM;
require $BASE_PM;
require "$FindBin::Bin/../hooks/lib/UserTools/Hook/AppSetup.pm";

*Cpanel::AccessIds::do_as_user = sub { return $_[1]->(); };

sub make_tree {
    my $root = tempdir( CLEANUP => 1 );
    my $home = "$root/home/newuser";
    make_path("$home/public_html");
    make_path("$root/bin");
    open my $cf, '>', "$root/usertools.conf" or die $!;
    print $cf "enable_app_helper=1\napp_packages=webapp,p1\n";
    close $cf;
    open my $wh, '>', "$root/bin/whmapi1" or die $!;
    print $wh <<'SCRIPT';
#!/bin/bash
printf '%s\n' "$@" >"$FAKE_WHM_ARGV"
printf '{"metadata":{"result":1}}\n'; exit 0
SCRIPT
    close $wh;
    chmod 0755, "$root/bin/whmapi1";
    open my $uh, '>', "$root/bin/uapi" or die $!;
    print $uh <<'SCRIPT';
#!/bin/bash
cat <<JSON
{"apiversion":3,"func":"domains_data","module":"DomainInfo","result":{"data":{"addon_domains":[],"main_domain":{"customlog":[{"format":"combined","target":"/etc/apache2/logs/domlogs/example.com"}],"documentroot":"$FAKE_DOMAININFO_DOCROOT","domain":"example.com","group":"newuser","hascgi":1,"homedir":"$home","ip":"192.0.2.10","is_temporary":0,"owner":"root","phpopenbasedirprotect":1,"port":"80","scriptalias":[{"path":"$home/public_html/cgi-bin","url":"/cgi-bin/"}],"serveradmin":"webmaster@example.com","serveralias":"mail.example.com www.example.com","servername":"example.com","status":"","type":"main_domain","usecanonicalname":"Off","user":"newuser"},"parked_domains":[],"sub_domains":[]},"errors":null,"messages":null,"metadata":{"transformed":1},"status":1,"warnings":null}}
JSON
exit 0
SCRIPT
    close $uh;
    chmod 0755, "$root/bin/uapi";
    %FAKE_PW = (
        newuser => [ 'newuser', 'x', 1001, 1001, '', '', '', $home, '/bin/bash' ] );
    $UserTools::Hook::AppSetup::CONF         = "$root/usertools.conf";
    $UserTools::Hook::AppSetup::WHMAPI1      = "$root/bin/whmapi1";
    $UserTools::Hook::AppSetup::UAPI         = "$root/bin/uapi";
    $UserTools::Hook::AppSetup::AUDIT_LOG    = "$root/audit.log";
    $UserTools::Hook::AppSetup::USERTOOLS_PM = $UTS_PM;
    $UserTools::Hook::AppSetup::BASE_PM      = $BASE_PM;
    $UserTools::Hook::AppSetup::DO_AS_USER   = sub { return $_[1]->(); };
    $Cpanel::API::UserTools::TEST_UAPI_BIN   = '/bin/false';
    return ( $root, $home );
}

# --- describe() ------------------------------------------------------------------
{
    my $d = UserTools::Hook::AppSetup::describe();
    is_deeply(
        $d,
        [
            {
                category => 'Whostmgr',
                event    => 'Accounts::Create',
                stage    => 'post',
                exectype => 'module',
                hook     => 'UserTools::Hook::AppSetup::hook',
            },
        ],
        'describe() arrayref for manage_hooks'
    );
}

# --- happy path ------------------------------------------------------------------
{
    my ( $root, $home ) = make_tree();
    local $ENV{FAKE_WHM_ARGV} = "$root/whm-argv.txt";
    local $ENV{FAKE_DOMAININFO_DOCROOT} = "$home/public_html/public";
    my $ctx = { category => 'Whostmgr', event => 'Accounts::Create', stage => 'post' };
    my $rc = UserTools::Hook::AppSetup::hook( $ctx, { data => { user => 'newuser', plan => 'webapp' } } );
    is( $rc, 1, 'hook returns 1 on success' );
    open my $ix, '<', "$home/public_html/public/index.php" or die "no placeholder: $!";
    my $ph = do { local $/; <$ix> };
    close $ix;
    like( $ph, qr/placeholder/i, 'placeholder index.php created as the user' );
    open my $pf, '<', "$home/public_html/public/.htaccess" or die $!;
    my $pub = do { local $/; <$pf> };
    close $pf;
    like( $pub, qr/Require all granted/, 'public htaccess written' );
    open my $rf, '<', "$home/public_html/.htaccess" or die $!;
    my $rht = do { local $/; <$rf> };
    close $rf;
    like( $rht, qr/Require all denied/, 'root locked afterwards' );
    open my $af, '<', "$root/whm-argv.txt" or die $!;
    my @argv = map { chomp; $_ } <$af>;
    close $af;
    ok( ( grep { $_ eq 'username=newuser' } @argv ) ? 1 : 0, 'hook username used' );
    ok( ( grep { $_ eq 'docroot=public_html/public' } @argv ) ? 1 : 0, 'hard-coded docroot' );
    open my $lf, '<', "$root/audit.log" or die "no audit log: $!";
    my $log = do { local $/; <$lf> };
    close $lf;
    like( $log, qr/newuser.*primary-docroot:public_html\/public/, 'audit line written' );
    is( ( stat("$root/audit.log") )[2] & 07777, 0600, 'audit log is 0600' );
}

# --- gating: package and feature ---------------------------------------------------
{
    my ( $root, $home ) = make_tree();
    local $ENV{FAKE_DOMAININFO_DOCROOT} = "$home/public_html/public";
    my $ctx = { category => 'Whostmgr', event => 'Accounts::Create', stage => 'post' };
    my $rc = UserTools::Hook::AppSetup::hook( $ctx, { user => 'newuser', package => 'basic' } );
    is( $rc, 1, 'unlisted package still returns 1' );
    ok( !-e "$home/public_html/public", 'unlisted package: nothing created' );

    open my $cf, '>', "$root/usertools.conf" or die $!;
    print $cf "enable_app_helper=0\napp_packages=webapp\n";
    close $cf;
    $rc = UserTools::Hook::AppSetup::hook( $ctx, { user => 'newuser', package => 'webapp' } );
    is( $rc, 1, 'disabled helper still returns 1' );
    ok( !-e "$home/public_html/public", 'disabled helper: nothing created' );
}

# --- failure never fails account creation ------------------------------------------
{
    my ( $root, $home ) = make_tree();
    local $ENV{FAKE_DOMAININFO_DOCROOT} = "$home/public_html/public";
    open my $wh, '>', "$root/bin/whmapi1" or die $!;
    print $wh "#!/bin/bash\nprintf '{\"metadata\":{\"result\":0,\"reason\":\"nope\"}}\\n'; exit 0\n";
    close $wh;
    chmod 0755, "$root/bin/whmapi1";
    my $ctx = { category => 'Whostmgr', event => 'Accounts::Create', stage => 'post' };
    my $rc = UserTools::Hook::AppSetup::hook( $ctx, { user => 'newuser', package => 'webapp' } );
    is( $rc, 0, 'WHM failure still returns 0' );
    open my $lf, '<', "$root/audit.log" or die "no audit log: $!";
    my $log = do { local $/; <$lf> };
    close $lf;
    like( $log, qr/app-setup failed/, 'failure logged' );

    $rc = UserTools::Hook::AppSetup::hook( $ctx, undef );
    is( $rc, 0, 'garbage data still returns 0' );
}

# --- The log names the blocking file -------------------------------------------
{
    my ( $root, $home ) = make_tree();
    local $ENV{FAKE_DOMAININFO_DOCROOT} = "$home/public_html/public";
    make_path("$home/public_html/public");
    open my $sk, '>', "$home/public_html/public/index.php" or die $!;
    print $sk "<?php // skeleton file\n";
    close $sk;
    my $ctx = { category => 'Whostmgr', event => 'Accounts::Create', stage => 'post' };
    my $rc = UserTools::Hook::AppSetup::hook( $ctx, { user => 'newuser', package => 'webapp' } );
    is( $rc, 0, 'skeleton clash still returns 0' );
    open my $lf, '<', "$root/audit.log" or die "no audit log: $!";
    my $log = do { local $/; <$lf> };
    close $lf;
    like( $log, qr/index\.php.*already exists|already exists.*index\.php/, 'blocking file named' );
}

# --- symlink refusal -----------------------------------------------------------------
{
    my ( $root, $home ) = make_tree();
    local $ENV{FAKE_DOMAININFO_DOCROOT} = "$home/public_html/public";
    rename "$home/public_html", "$home/real_html" or die $!;
    symlink "$home/real_html", "$home/public_html" or die $!;
    my $ctx = { category => 'Whostmgr', event => 'Accounts::Create', stage => 'post' };
    my $rc = UserTools::Hook::AppSetup::hook( $ctx, { user => 'newuser', package => 'webapp' } );
    is( $rc, 0, 'symlink refusal still returns 0' );
    ok( !-e "$home/real_html/public", 'symlinked public_html refused' );
    open my $lf, '<', "$root/audit.log" or die "no audit log: $!";
    my $log = do { local $/; <$lf> };
    close $lf;
    like( $log, qr/refusing symlink/, 'refusal logged' );
}

done_testing();
