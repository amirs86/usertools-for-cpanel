# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for Cpanel/API/UserTools.pm, runnable WITHOUT a cPanel
# server:  prove -Itests/lib tests/test_usertools_pm.t
#
# Technique: tests/lib/ holds empty stubs for the Cpanel::* modules the plugin
# uses at compile time. Behavioural seams:
#   * $Cpanel::API::UserTools::TEST_USER / TEST_HOME — caller identity
#     (production: getpwuid($>); UAPI callers cannot set these).
#   * CORE::GLOBAL::lstat — delegates to the real lstat, then patches st_uid /
#     st_gid for chosen paths (file TYPE bits are never faked, so `-l _`,
#     `-f _`, `-d _` stay truthful).
#   * CORE::GLOBAL::getgrnam/getgrgid — alias the expected test groups to the
#     fixture's real gid, or inject 'nobody' for FileProtect tests.
# Modes, symlinks, mkdir and chmod are all exercised for real on a File::Temp
# home directory.
use strict;
use warnings;
no warnings 'once';    # package-var seams ($TEST_*, %CPDATA, hasfeature) are set once
use Test::More;
use FindBin;
use File::Temp qw(tempdir);
use File::Path qw(make_path);

use lib "$FindBin::Bin/lib";

our ( %FAKE_UID, %FAKE_GID, %FAKE_GRPNAME, %FAKE_ERRNO );
our $HAVE_FEATURE = 1;

my $REAL_GID;

BEGIN {
    require Errno;
    *CORE::GLOBAL::lstat = sub {
        if ( exists $FAKE_ERRNO{ $_[0] } ) {
            my $name = $FAKE_ERRNO{ $_[0] };
            $! = ( $name eq 'EACCES' ) ? Errno::EACCES() : Errno::ENOENT();
            return;
        }
        my @st = CORE::lstat( $_[0] );
        return unless @st;
        my $p = $_[0];
        $st[4] = $FAKE_UID{$p} if exists $FAKE_UID{$p};
        $st[5] = $FAKE_GID{$p} if exists $FAKE_GID{$p};
        return @st;
    };
    *CORE::GLOBAL::getgrnam = sub {
        my ($name) = @_;
        if ( $name eq 'testuser' || $name eq 'mail' ) {
            return ( 'x', 'x', $REAL_GID );    # alias to the fixture group
        }
        return CORE::getgrnam($name);
    };
    *CORE::GLOBAL::getgrgid = sub {
        my ($gid) = @_;
        return $FAKE_GRPNAME{$gid} if exists $FAKE_GRPNAME{$gid};
        return scalar CORE::getgrgid($gid);
    };
    *CORE::GLOBAL::getpwnam = sub {
        my ($name) = @_;
        # Fixture identity follows the TEST_HOME seam (the fallback reads
        # getpwnam; single tests may local-override this further).
        if ( $name eq 'testuser' && defined $Cpanel::API::UserTools::TEST_HOME ) {
            my $h = $Cpanel::API::UserTools::TEST_HOME;
            return ( 'testuser', 'x', 1000, 1000, '', '', '', $h, '/bin/bash' );
        }
        return CORE::getpwnam($name);
    };
}

require "$FindBin::Bin/../Cpanel/API/UserTools.pm";

*main::hasfeature = sub { return $HAVE_FEATURE; };

# --- tiny UAPI arg/result doubles -------------------------------------------
package FakeArgs;
sub new {
    my ( $class, %params ) = @_;
    return bless {%params}, $class;
}
sub get {
    my ( $self, @names ) = @_;
    return map { $self->{$_} } @names;
}

package FakeResult;
sub new { return bless { data => undef, errors => [] }, shift; }
sub data { $_[0]->{data} = $_[1]; }
sub error { push @{ $_[0]->{errors} }, [ @_[ 1 .. $#_ ] ]; }

# Mirrors Cpanel::Result's real signatures on 11.138 — error() takes a
# maketext pattern plus args, raw_error() takes exactly one literal string.
sub raw_error {
    if ( @_ != 2 ) {
        die "raw_error takes exactly 1 argument (got @{[ scalar(@_) - 1 ]})";
    }
    push @{ $_[0]->{errors} }, [ $_[1] ];
}

package main;

# --- fixture -----------------------------------------------------------------
sub make_home {
    my $home = tempdir( CLEANUP => 1 );
    $REAL_GID = ( CORE::lstat($home) )[5];
    $Cpanel::API::UserTools::TEST_USER = 'testuser';
    $Cpanel::API::UserTools::TEST_HOME = $home;
    %FAKE_UID = ();
    %FAKE_GID = ();
    %FAKE_GRPNAME = ();
    %FAKE_ERRNO = ();
    return $home;
}

sub row_by_key {
    my ( $rows, $key ) = @_;
    for my $r ( @{$rows} ) {
        return $r if $r->{key} eq $key;
    }
    return undef;
}

sub call_check {
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::home_permissions_check( FakeArgs->new(), $res );
    return ( $ok, $res );
}

sub call_fix {
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::home_permissions_fix( FakeArgs->new(), $res );
    return ( $ok, $res );
}

# --- %API metadata -------------------------------------------------------------
is(
    $Cpanel::API::UserTools::API{home_permissions_check}{needs_feature},
    'usertools_fix_home',
    '%API declares needs_feature for check'
);
is(
    $Cpanel::API::UserTools::API{home_permissions_fix}{needs_feature},
    'usertools_fix_home',
    '%API declares needs_feature for fix'
);
is(
    $Cpanel::API::UserTools::API{home_permissions_undo}{needs_feature},
    'usertools_fix_home',
    '%API declares needs_feature for undo'
);

# --- feature + demo gates -------------------------------------------------------
{
    my $home = make_home();
    local $HAVE_FEATURE = 0;
    my ( $ok, $res ) = call_check();
    ok( !$ok, 'check refused without the feature' );
    is( $res->{errors}[0][0], '_ERROR_FEATURE', 'feature error reported' );
    ( $ok, $res ) = call_fix();
    ok( !$ok, 'fix refused without the feature' );
}
{
    my $home = make_home();
    local $Cpanel::CPDATA{DEMO} = 1;
    my ( $ok, $res ) = call_check();
    ok( !$ok, 'check refused in demo mode' );
    is( $res->{errors}[0][0], '_ERROR_DEMO_MODE', 'demo error reported' );
}

# --- green check + mode mismatch + fix ------------------------------------------
{
    my $home = make_home();
    make_path("$home/tmp");
    chmod 0755, "$home/tmp";
    my ( $ok, $res ) = call_check();
    ok( $ok, 'check returns true' );
    my $tmp = row_by_key( $res->{data}{rows}, 'tmp' );
    is( $tmp->{status},      'ok',   'tmp row ok' );
    is( $tmp->{current_mode}, '0755', 'current mode reported' );
    is( $res->{data}{user},  'testuser', 'username reported' );

    chmod 0700, "$home/tmp";
    ( $ok, $res ) = call_check();
    $tmp = row_by_key( $res->{data}{rows}, 'tmp' );
    is( $tmp->{status}, 'mode_mismatch', 'wrong mode detected' );

    ( $ok, $res ) = call_fix();
    ok( $ok, 'fix returns true' );
    my $fix = row_by_key( $res->{data}{paths}, 'tmp' );
    is( $fix->{action}, 'fixed', 'tmp fixed' );
    is( $fix->{from},   '0700',  'fix reports old mode' );
    is( $fix->{to},     '0755',  'fix reports new mode' );
    is( ( CORE::lstat("$home/tmp") )[2] & 07777, 0755, 'mode really changed' );

    ( $ok, $res ) = call_check();
    is( row_by_key( $res->{data}{rows}, 'tmp' )->{status}, 'ok', 'green after fix' );
}

# --- missing: creatable vs not ---------------------------------------------------
{
    my $home = make_home();    # tmp and .ssh absent
    my ( $ok, $res ) = call_check();
    is( row_by_key( $res->{data}{rows}, 'tmp' )->{status}, 'missing', 'tmp missing reported' );
    ( $ok, $res ) = call_fix();
    is( row_by_key( $res->{data}{paths}, 'tmp' )->{action}, 'created', 'tmp created' );
    is( ( CORE::lstat("$home/tmp") )[2] & 07777, 0755, 'tmp created with exact mode' );
    is( row_by_key( $res->{data}{paths}, 'ssh' )->{action}, 'created', '.ssh created' );
    is( ( CORE::lstat("$home/.ssh") )[2] & 07777, 0700, '.ssh created with exact mode' );
    is( row_by_key( $res->{data}{paths}, 'authorized_keys' )->{action },
        'missing', 'authorized_keys not auto-created' );
    is( row_by_key( $res->{data}{paths}, 'etc' )->{action}, 'missing', 'etc not created' );
}

# --- symlinks refused -------------------------------------------------------------
{
    my $home = make_home();
    make_path("$home/real_tmp");
    chmod 0755, "$home/real_tmp";
    symlink "$home/real_tmp", "$home/tmp" or die "symlink failed: $!";
    my ( $ok, $res ) = call_check();
    is( row_by_key( $res->{data}{rows}, 'tmp' )->{status}, 'symlink', 'symlink reported' );
    ( $ok, $res ) = call_fix();
    is( row_by_key( $res->{data}{paths}, 'tmp' )->{action },
        'skipped_symlink', 'symlink skipped by fix' );
    is( ( CORE::lstat("$home/real_tmp") )[2] & 07777, 0755, 'symlink target untouched' );
    ok( -l "$home/tmp", 'link itself still a link' );
}

# --- small (c): missing authorized_keys is informational when the account has no SSH key ------------
{
    my $home = make_home();    # no .ssh, no keys at all
    my ( $ok, $res ) = call_check();
    my $row = row_by_key( $res->{data}{rows}, 'authorized_keys' );
    is( $row->{status}, 'missing', 'missing keys file reported' );
    is( $row->{informational}, 1, 'small (c): flagged informational without a key' );
    $row = row_by_key( $res->{data}{rows}, 'ssh' );
    is( $row->{status}, 'missing', 'missing .ssh reported' );
    is( $row->{informational}, 1, 'missing .ssh informational without a key' );

    # With a key present the row is not informational.
    make_path("$home/.ssh");
    open my $fh, '>', "$home/.ssh/authorized_keys" or die $!;
    print $fh "ssh-ed25519 AAAATEST user\@host\n";
    close $fh;
    chmod 0600, "$home/.ssh/authorized_keys";
    ( $ok, $res ) = call_check();
    $row = row_by_key( $res->{data}{rows}, 'authorized_keys' );
    is( $row->{status}, 'ok', 'key file accepted' );
    ok( !defined $row->{informational}, 'small (c): no flag when a key exists' );
}

# --- owner mismatch (mocked uid): reported, never touched ---------------------------
{
    my $home = make_home();
    make_path("$home/mail");
    chmod 0700, "$home/mail";    # also a wrong mode on purpose
    local $FAKE_UID{"$home/mail"} = 0;
    my ( $ok, $res ) = call_check();
    my $row = row_by_key( $res->{data}{rows}, 'mail' );
    is( $row->{status},        'owner_mismatch', 'owner mismatch detected' );
    is( $row->{current_owner}, 'root',           'owner name reported' );
    ( $ok, $res ) = call_fix();
    is( row_by_key( $res->{data}{paths}, 'mail' )->{action }, 'not_owned', 'not-owned fix refused' );
    is( ( CORE::lstat("$home/mail") )[2] & 07777, 0700, 'not-owned mode untouched' );
}

# --- group mismatch (mocked gid) ------------------------------------------------------
{
    my $home = make_home();
    make_path("$home/tmp");
    chmod 0755, "$home/tmp";
    local $FAKE_GID{"$home/tmp"} = 424243;
    local $FAKE_GRPNAME{424243} = 'othergroup';
    my ( $ok, $res ) = call_check();
    my $row = row_by_key( $res->{data}{rows}, 'tmp' );
    is( $row->{owner_ok}, 1,                'owner still ok' );
    is( $row->{group_ok}, 0,                'group mismatch detected' );
    is( $row->{status},   'owner_mismatch', 'group mismatch needs provider' );
    is( $row->{current_group}, 'othergroup', 'group name reported' );
}

# --- FileProtect: touch-file rules ----------------------------------------------------------
{
    my $home = make_home();
    make_path("$home/public_html");
    my $touch = "$home/fileprotect";
    is( Cpanel::API::UserTools::_fileprotect_on( $home, "$home/no-such-file" ),
        0, 'absent touch file means OFF (no heuristic)' );
    open my $fh, '>', $touch or die "cannot create $touch: $!";
    close $fh;
    is( Cpanel::API::UserTools::_fileprotect_on( $home, $touch ),
        1, 'present touch file means ON (group ignored)' );
    my ( $ok, $res ) = call_check();
    is( $res->{data}{fileprotect}, 0, 'absent default touch file means OFF' );
    my $ph = row_by_key( $res->{data}{rows}, 'public_html' );
    is( $ph->{required_mode},  '0755',     'off variant mode' );
    is( $ph->{required_group}, 'testuser', 'off variant group' );
}
{
    # EACCES on the touch file -> public_html group heuristic.
    my $home = make_home();
    make_path("$home/public_html");
    my $touch = "$home/fileprotect";
    open my $fh, '>', $touch or die "cannot create $touch: $!";
    close $fh;
    my $gid = ( CORE::lstat("$home/public_html") )[5];
    local $FAKE_ERRNO{$touch} = 'EACCES';
    local $FAKE_GRPNAME{$gid} = 'nobody';
    is( Cpanel::API::UserTools::_fileprotect_on( $home, $touch ),
        1, 'EACCES falls back to group heuristic (nobody -> ON)' );
}
{
    # EACCES with a normal group -> OFF, exercised through check().
    my $home = make_home();
    make_path("$home/public_html");
    local $FAKE_ERRNO{'/var/cpanel/fileprotect'} = 'EACCES';
    my ( $ok, $res ) = call_check();
    is( $res->{data}{fileprotect}, 0, 'EACCES + normal group means OFF' );
    my $gid = ( CORE::lstat("$home/public_html") )[5];
    local $FAKE_GRPNAME{$gid} = 'nobody';
    ( $ok, $res ) = call_check();
    is( $res->{data}{fileprotect}, 1, 'EACCES + nobody group means ON' );
    my $ph = row_by_key( $res->{data}{rows}, 'public_html' );
    is( $ph->{required_mode},  '0750',   'on variant mode' );
    is( $ph->{required_group}, 'nobody', 'on variant group' );
}

# --- special files skipped by fix ----------------------------------------------------------
{
    my $home = make_home();
    make_path("$home/ssl");
    my $fifo = "$home/ssl/ssl.db";
    require POSIX;
    POSIX::mkfifo( $fifo, 0600 ) or die "mkfifo failed: $!";
    my ( $ok, $res ) = call_fix();
    is( row_by_key( $res->{data}{paths}, 'ssl_db' )->{action },
        'skipped_special', 'fifo skipped by fix' );
}

# --- undo journal + undo -------------------------------------------------------------
sub call_undo {
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::home_permissions_undo( FakeArgs->new(), $res );
    return ( $ok, $res );
}

{
    my $home = make_home();
    chmod 0711, $home;    # home row already correct: only tmp gets journaled
    make_path("$home/tmp");
    chmod 0700, "$home/tmp";
    my ( $ok, $res ) = call_fix();
    ok( $ok, 'fix returns true' );
    my $journal = $res->{data}{undo_journal};
    ok( defined $journal, 'fix wrote an undo journal' );
    like( $journal, qr/^fixhome-.*\.jsonl\.gz$/, 'journal name shape' );
    ok( -f "$home/.cpanel/usertools/undo/$journal", 'journal file exists' );
    is( ( CORE::lstat("$home/tmp") )[2] & 07777, 0755, 'mode fixed' );

    ( $ok, $res ) = call_check();
    is( $res->{data}{undo_available}, 1, 'undo advertised by check' );
    is( $res->{data}{undo_journal}, $journal, 'check names the journal' );
    is( scalar( @{ $res->{data}{undo_history} } ), 1, 'history lists one run' );
    ok( $res->{data}{undo_history}[0]{bytes} > 0, 'history entry has size' );
    ok( $res->{data}{undo_history}[0]{started} > 0, 'history entry has time' );

    chmod 0700, "$home/tmp";    # break it again so undo has work to do
    ( $ok, $res ) = call_undo();
    ok( $ok, 'undo returns true but restores nothing (changed since)' );
    is( $res->{data}{restored}, 0, 'changed-since entry skipped' );
    is( ( CORE::lstat("$home/tmp") )[2] & 07777, 0700, 'left alone' );

    chmod 0755, "$home/tmp";    # back to the recorded post-fix state
    ( $ok, $res ) = call_undo();
    ok( $ok, 'undo returns true' );
    is( $res->{data}{restored}, 1, 'one path restored' );
    is( ( CORE::lstat("$home/tmp") )[2] & 07777, 0700, 'mode restored' );

    ( $ok, $res ) = call_undo();
    is( $res->{data}{restored}, 0, 'second undo is a no-op (already restored)' );
}

{
    # Undo skips symlink swaps and changed-since entries.
    my $home = make_home();
    make_path("$home/tmp");
    chmod 0700, "$home/tmp";
    my ( $ok, $res ) = call_fix();
    my $journal = $res->{data}{undo_journal};
    ok( defined $journal, 'journal written' );

    make_path("$home/real");
    chmod 0755, "$home/real";
    rmdir "$home/tmp" or die "rmdir failed: $!";
    symlink "$home/real", "$home/tmp" or die "symlink failed: $!";
    ( $ok, $res ) = call_undo();
    my ($entry) = grep { $_->{key} eq 'tmp' } @{ $res->{data}{paths} };
    is( $entry->{action}, 'skipped_symlink', 'swapped-in symlink skipped' );
    ok( -l "$home/tmp", 'link left alone' );
}

{
    # No journal yet: undo is an empty success.
    my $home = make_home();
    my ( $ok, $res ) = call_undo();
    ok( $ok, 'undo with no journal succeeds' );
    is( $res->{data}{restored}, 0, 'nothing restored' );
    is_deeply( $res->{data}{paths}, [], 'no paths' );
}

# --- maketext routing ------------------------------------------------------------------
{
    my $home = make_home();
    make_path("$home/real_tmp");
    symlink "$home/real_tmp", "$home/tmp" or die "symlink failed: $!";
    my ( $ok, $res ) = call_fix();
    my $row = row_by_key( $res->{data}{paths}, 'tmp' );
    like( $row->{detail}, qr/^T:/, 'detail routed through maketext' );

    no warnings 'redefine';
    local *Cpanel::Locale::get_handle = sub { die "no locale here\n"; };
    ( $ok, $res ) = call_fix();
    $row = row_by_key( $res->{data}{paths}, 'tmp' );
    unlike( $row->{detail}, qr/^T:/, 'English fallback without locale' );
    like( $row->{detail}, qr/symlink/, 'fallback text intact' );
}

# --- bulk: %API, validation -----------------------------------------------------------
is(
    $Cpanel::API::UserTools::API{bulk_permissions_start}{needs_feature},
    'usertools_bulk_perms',
    '%API declares needs_feature for bulk start'
);
is(
    $Cpanel::API::UserTools::API{bulk_permissions_status}{needs_feature},
    'usertools_bulk_perms',
    '%API declares needs_feature for bulk status'
);
is(
    $Cpanel::API::UserTools::API{bulk_permissions_cancel}{needs_feature},
    'usertools_bulk_perms',
    '%API declares needs_feature for bulk cancel'
);
is(
    $Cpanel::API::UserTools::API{bulk_permissions_undo}{needs_feature},
    'usertools_bulk_perms',
    '%API declares needs_feature for bulk undo'
);

{
    my $home = make_home();
    my $res  = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => '/etc' ), $res );
    ok( !$ok, 'outside-home scope refused' );
    like( $res->{errors}[0][1], qr/outside your home/, 'scope reason given' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => "$home/.ssh" ), $res );
    ok( !$ok, 'protected scope refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => 'public_html', exclude => [ (map { "p$_" } 1 .. 21) ] ), $res );
    ok( !$ok, 'too many excludes refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_status(
        FakeArgs->new( job_id => '../../etc/x' ), $res );
    ok( !$ok, 'traversal job id refused' );
    is( $res->{errors}[0][0], 'Unknown job.', 'unknown job literal' );
}

# --- bulk: live start/status/undo (spawns the real engine) ---------------------------
use Fcntl qw(:flock);

$Cpanel::API::UserTools::TEST_ENGINE_BIN = 'python3';
$Cpanel::API::UserTools::TEST_ENGINE    = "$FindBin::Bin/../engine/perm_engine.py";
$ENV{USERTOOLS_TESTING} = '1';

sub make_bulk_home {
    my $home = make_home();
    make_path("$home/public_html/sub");
    for my $f (qw(index.html app.css)) {
        open my $fh, '>', "$home/public_html/$f" or die $!;
        print $fh "x\n";
        close $fh;
        chmod 0600, "$home/public_html/$f";
    }
    open my $fh, '>', "$home/public_html/sub/page.html" or die $!;
    print $fh "x\n";
    close $fh;
    chmod 0600, "$home/public_html/sub/page.html";
    chmod 0700, "$home/public_html/sub";
    return $home;
}

sub start_job {
    my ( $home, %params ) = @_;
    $params{scope} = 'public_html' unless exists $params{scope};
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_start( FakeArgs->new(%params), $res );
    return ( $ok, $res );
}

sub wait_job_done {
    my ($job_id) = @_;
    for ( 1 .. 200 ) {
        my $res = FakeResult->new();
        my $ok = Cpanel::API::UserTools::bulk_permissions_status(
            FakeArgs->new( job_id => $job_id ), $res );
        if ( $ok && $res->{data}{state} eq 'done' ) {
            return $res;
        }
        select( undef, undef, undef, 0.1 );
    }
    die "job $job_id did not finish";
}

{
    my $home = make_bulk_home();
    my ( $ok, $res ) = start_job( $home, dry_run => '1' );
    ok( $ok, 'dry-run start accepted' );
    my $job_id = $res->{data}{job_id};
    like( $job_id, qr/^bulk-/, 'job id shape' );
    my $st = wait_job_done($job_id);
    my $summary = $st->{data}{summary};
    ok( $summary->{counts}{would_change} >= 4, 'preview counts changes' );
    is( $summary->{counts}{changed}, 0, 'preview changed nothing' );
    is( $st->{data}{dry_run}, 1, 'status reports dry run' );
    is( ( CORE::lstat("$home/public_html/index.html") )[2] & 07777,
        0600, 'preview left modes alone' );
}

{
    my $home = make_bulk_home();
    my ( $ok, $res ) = start_job( $home, dry_run => '0' );
    ok( $ok, 'real start accepted' );
    my $st = wait_job_done( $res->{data}{job_id} );
    my $summary = $st->{data}{summary};
    ok( $summary->{counts}{changed} >= 4, 'real run changed files' );
    is( ( CORE::lstat("$home/public_html/index.html") )[2] & 07777,
        0644, 'mode really fixed' );
    ok( ref $st->{data}{history} eq 'ARRAY', 'status carries history' );

    # Undo the bulk run through the module (async: spawns an undo job).
    my $ures = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_undo( FakeArgs->new(), $ures );
    ok( $ok, 'bulk undo accepted' );
    like( $ures->{data}{job_id}, qr/^undo-/, 'small (d): undo spawns a background job' );
    my $ust = wait_job_done( $ures->{data}{job_id} );
    ok( $ust->{data}{summary}{counts}{changed} >= 4, 'bulk modes restored' );
    is( ( CORE::lstat("$home/public_html/index.html") )[2] & 07777,
        0600, 'mode restored' );
}

{
    # 3 Fix Home journals + a Bulk apply -> Bulk undo still restores
    # (pruning is per tool prefix, so fixhome-* never evicts bulk-*).
    my $home = make_bulk_home();
    make_path("$home/tmp");
    for ( 1 .. 3 ) {
        chmod 0700, "$home/tmp";
        my ( $fok, $fres ) = call_fix();
        ok( $fok && defined $fres->{data}{undo_journal}, 'fixhome journal written' );
    }
    my ( $ok, $res ) = start_job( $home, dry_run => '0' );
    ok( $ok, 'bulk start accepted after 3 fixhome journals' );
    my $st = wait_job_done( $res->{data}{job_id} );
    ok( $st->{data}{summary}{counts}{changed} >= 4, 'bulk apply changed files' );

    # Even a 4th fixhome run afterwards must not evict the bulk journal.
    chmod 0700, "$home/tmp";
    call_fix();

    my $ures = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_undo( FakeArgs->new(), $ures );
    ok( $ok, 'bulk undo accepted after fixhome journals' );
    my $ust = wait_job_done( $ures->{data}{job_id} );
    ok( $ust->{data}{summary}{counts}{changed} >= 4, 'bulk undo restored all changed modes' );
    is( ( CORE::lstat("$home/public_html/index.html") )[2] & 07777,
        0600, 'index.html mode restored to 0600' );
}

# --- small (d): undo busy reattach + empty history -------------------------------
{
    my $home = make_bulk_home();
    my $ures = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_undo( FakeArgs->new(), $ures );
    ok( $ok, 'undo with no journal accepted' );
    is( $ures->{data}{state}, 'done', 'no journal reports done synchronously' );
    is( $ures->{data}{restored}, 0, 'nothing restored' );
}

# --- bulk cancel ----------------------------------------------------------------
sub write_fake_job {
    my ( $home, $id, $pid ) = @_;
    my $dir = "$home/.cpanel/usertools/jobs";
    make_path($dir);
    open my $fh, '>', "$dir/$id.job.json" or die $!;
    print $fh JSON::PP->new()->encode( { id => $id, pid => $pid + 0 } );
    close $fh;
    return $id;
}

{
    # Stale pid + stale lock file: reported finished, nothing killed.
    my $home = make_bulk_home();
    my $lock = "$home/.cpanel/usertools";
    make_path($lock);
    open my $lfh, '>', "$lock/perm_engine.lock" or die $!;
    close $lfh;
    my $id = write_fake_job( $home, 'bulk-test-stale1', 2**30 );
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_cancel(
        FakeArgs->new( job_id => $id ), $res );
    ok( $ok, 'stale cancel is not an error' );
    is( $res->{data}{cancelled}, 0, 'nothing cancelled' );
}

{
    # Live foreign-uid refusal (owner check mocked to fail).
    my $home = make_bulk_home();
    my $sleep = fork();
    die "fork failed: $!" unless defined $sleep;
    if ( $sleep == 0 ) {
        exec 'sleep', '120';
        POSIX::_exit(1);
    }
    my $id = write_fake_job( $home, 'bulk-test-foreign1', $sleep );
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_proc_owner_ok = sub { 0 };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_cancel(
        FakeArgs->new( job_id => $id ), $res );
    ok( !$ok, 'foreign process refused' );
    is( $res->{errors}[0][0],
        'Refusing to stop a process owned by another account.', 'refusal literal' );
    ok( kill( 0, $sleep ), 'foreign-looking process still alive' );
    kill( 'KILL', $sleep );
    waitpid( $sleep, 0 );
}

{
    # Cmdline mismatch (own sleep, not our engine): treated as stale.
    my $home = make_bulk_home();
    my $sleep = fork();
    die "fork failed: $!" unless defined $sleep;
    if ( $sleep == 0 ) {
        exec 'sleep', '120';
        POSIX::_exit(1);
    }
    my $id = write_fake_job( $home, 'bulk-test-cmdline1', $sleep );
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_cancel(
        FakeArgs->new( job_id => $id ), $res );
    ok( $ok, 'cmdline mismatch is not an error' );
    is( $res->{data}{cancelled}, 0, 'nothing cancelled' );
    ok( kill( 0, $sleep ), 'unrelated process still alive' );
    kill( 'KILL', $sleep );
    waitpid( $sleep, 0 );
}

{
    # Happy path: own engine-looking process + held lock -> SIGTERM.
    my $home = make_bulk_home();
    my $lockdir = "$home/.cpanel/usertools";
    make_path($lockdir);
    open my $lfh, '>>', "$lockdir/perm_engine.lock" or die $!;
    flock( $lfh, LOCK_EX ) or die "flock failed: $!";
    my $sleep = fork();
    die "fork failed: $!" unless defined $sleep;
    if ( $sleep == 0 ) {
        exec 'sleep', '120';
        POSIX::_exit(1);
    }
    my $id = write_fake_job( $home, 'bulk-test-kill1', $sleep );
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_proc_is_engine = sub { 1 };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_cancel(
        FakeArgs->new( job_id => $id ), $res );
    ok( $ok, 'cancel accepted' );
    is( $res->{data}{cancelled}, 1, 'process stopped' );
    ok( !kill( 0, $sleep ), 'process really dead' );
    ok( -f "$home/.cpanel/usertools/jobs/$id.cancelled", 'small (a): cancel writes the cancelled marker' );
    close $lfh;

    # Status of a cancelled job with a partial summary: 'cancelled', not 'done'.
    open my $rfh, '>', "$home/.cpanel/usertools/jobs/$id.result.json" or die $!;
    print $rfh JSON::PP->new()->encode( { counts => { scanned => 5, changed => 2 } } );
    close $rfh;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_status(
        FakeArgs->new( job_id => $id ), $res );
    ok( $ok, 'status accepted after cancel' );
    is( $res->{data}{state}, 'cancelled', 'small (a): cancelled job reports cancelled' );
    is_deeply( $res->{data}{summary}{counts}, { scanned => 5, changed => 2 },
        'small (a): partial summary still attached' );
}

# --- bulk: strict booleans -----------------------------------------------------------------
{
    is( Cpanel::API::UserTools::_bool_param( 'false', 1 ), 0, '"false" is false' );
    is( Cpanel::API::UserTools::_bool_param( '0',     1 ), 0, '"0" is false' );
    is( Cpanel::API::UserTools::_bool_param( 'no',    1 ), 0, '"no" is false' );
    is( Cpanel::API::UserTools::_bool_param( 'off',   1 ), 0, '"off" is false' );
    is( Cpanel::API::UserTools::_bool_param( 'TRUE',  0 ), 1, '"TRUE" is true' );
    is( Cpanel::API::UserTools::_bool_param( 'Yes',   0 ), 1, '"Yes" is true' );
    is( Cpanel::API::UserTools::_bool_param( 'on',    0 ), 1, '"on" is true' );
    is( Cpanel::API::UserTools::_bool_param( undef,   1 ), 1, 'missing takes default' );
    my ( $v, $err ) = Cpanel::API::UserTools::_bool_param( 'maybe', 1 );
    ok( !defined $v && defined $err, 'garbage rejected with reason' );
    my $home = make_bulk_home();
    my $res  = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => 'public_html', dry_run => 'sometimes' ), $res );
    ok( !$ok, 'garbage dry_run refused by start' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => 'public_html', harden => 'false' ), $res );
    ok( $ok, '"false" harden accepted as off' );
}

# --- bulk: excludes JSON shape + repeated-key compat ---------------------------------------
{
    my $home = make_bulk_home();
    my $packed = JSON::PP->new()->encode( ['sub/*'] );
    my ( $ok, $res ) = start_job( $home, dry_run => '1', excludes => $packed );
    ok( $ok, 'JSON excludes accepted' );
    my $st = wait_job_done( $res->{data}{job_id} );
    my $paths = $st->{data}{summary}{paths}{would_change} || [];
    my $dump = join( "\n", map { ref $_ ? $_->{path} : $_ } @{$paths} );
    unlike( $dump, qr{sub/}, 'excluded subtree untouched by preview' );
    like( $dump, qr{index\.html}, 'rest still previewed' );
}
{
    my $home = make_bulk_home();
    my ( $ok, $res ) = start_job( $home, dry_run => '1', exclude => 'sub/*' );
    ok( $ok, 'repeated exclude key still accepted' );
    my $st = wait_job_done( $res->{data}{job_id} );
    is( $st->{data}{state}, 'done', 'compat preview finishes' );
}
{
    my $home = make_bulk_home();
    my $res  = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => 'public_html', excludes => 'not json' ), $res );
    ok( !$ok, 'broken JSON excludes refused' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => 'public_html', excludes => '[{}]' ), $res );
    ok( !$ok, 'object elements refused (never stringified)' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => 'public_html', excludes => '[' . ( 'x' x 8193 ) . ']' ), $res );
    ok( !$ok, 'oversize excludes refused before decoding' );
}

# --- bulk: busy reattach ----------------------------------------------------------------------
{
    my $home = make_bulk_home();
    my $lockdir = "$home/.cpanel/usertools";
    make_path($lockdir);
    open my $lfh, '>>', "$lockdir/perm_engine.lock" or die $!;
    flock( $lfh, LOCK_EX ) or die "flock failed: $!";
    my $sleep = fork();
    die "fork failed: $!" unless defined $sleep;
    if ( $sleep == 0 ) {
        exec 'sleep', '120';
        POSIX::_exit(1);
    }
    my $dir = "$home/.cpanel/usertools/jobs";
    make_path($dir);
    my $id = 'bulk-test-busy1';
    open my $fh, '>', "$dir/$id.job.json" or die $!;
    print $fh JSON::PP->new()->encode(
        { id => $id, pid => $sleep + 0, scope => "$home/public_html", dry_run => 1 } );
    close $fh;
    my $before = scalar grep { /\.job\.json$/ } do {
        opendir( my $dh, $dir ) or die $!;
        my @f = readdir $dh;
        closedir $dh;
        @f;
    };
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_proc_is_engine = sub { 1 };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::bulk_permissions_start(
        FakeArgs->new( scope => 'public_html' ), $res );
    ok( $ok, 'busy start is not an error' );
    is( $res->{data}{state}, 'busy', 'busy state returned' );
    is( $res->{data}{job_id}, $id, 'reattaches to the running job' );
    my $after = scalar grep { /\.job\.json$/ } do {
        opendir( my $dh2, $dir ) or die $!;
        my @f = readdir $dh2;
        closedir $dh2;
        @f;
    };
    is( $after, $before, 'no new job spawned while busy' );
    close $lfh;
    kill( 'KILL', $sleep );
    waitpid( $sleep, 0 );
}

# --- bulk: job pruning ----------------------------------------------------------------------------
sub seed_finished_job {
    my ( $home, $id, $age ) = @_;
    my $dir = "$home/.cpanel/usertools/jobs";
    make_path($dir);
    open my $fh, '>', "$dir/$id.job.json" or die $!;
    print $fh JSON::PP->new()->encode( { id => $id, pid => 2**30 } );
    close $fh;
    for my $ext (qw(progress.json result.json stderr.log)) {
        open my $fh2, '>', "$dir/$id.$ext" or die $!;
        print $fh2 '{}';
        close $fh2;
    }
    my $t = time() - $age;
    for my $ext (qw(job.json progress.json result.json stderr.log)) {
        utime $t, $t, "$dir/$id.$ext";
    }
    return $id;
}

{
    my $home = make_home();
    for my $i ( 1 .. 12 ) {
        seed_finished_job( $home, sprintf( 'bulk-test-prune%02d', $i ), ( 13 - $i ) * 100 );
    }
    my $sleep = fork();
    die "fork failed: $!" unless defined $sleep;
    if ( $sleep == 0 ) {
        exec 'sleep', '120';
        POSIX::_exit(1);
    }
    seed_finished_job( $home, 'bulk-test-live1', 50 );
    # rewrite the live one with a live pid and no summary
    my $dir = "$home/.cpanel/usertools/jobs";
    open my $fh, '>', "$dir/bulk-test-live1.job.json" or die $!;
    print $fh JSON::PP->new()->encode( { id => 'bulk-test-live1', pid => $sleep + 0 } );
    close $fh;
    unlink "$dir/bulk-test-live1.result.json";
    Cpanel::API::UserTools::_prune_jobs($home);
    opendir( my $dh, $dir ) or die $!;
    my @left = sort grep { /\.job\.json$/ } readdir $dh;
    closedir $dh;
    is( scalar(@left), 11, '10 finished + 1 live kept' );
    ok( !-f "$dir/bulk-test-prune01.job.json", 'oldest pruned' );
    ok( !-f "$dir/bulk-test-prune02.job.json", 'second oldest pruned' );
    ok( !-f "$dir/bulk-test-prune01.progress.json", 'pruned job files all gone' );
    ok( -f "$dir/bulk-test-live1.job.json", 'live job never pruned' );
    kill( 'KILL', $sleep );
    waitpid( $sleep, 0 );
}

{
    # start() itself prunes: seed 11 finished, run one dry job, oldest is gone.
    my $home = make_bulk_home();
    for my $i ( 0 .. 10 ) {
        seed_finished_job( $home, sprintf( 'bulk-test-old%02d', $i ), ( 20 - $i ) * 100 );
    }
    my ( $ok, $res ) = start_job( $home, dry_run => '1' );
    ok( $ok, 'start accepted' );
    my $new_id = $res->{data}{job_id};
    wait_job_done($new_id);
    my $dir = "$home/.cpanel/usertools/jobs";
    ok( !-f "$dir/bulk-test-old00.job.json", 'start pruned the oldest job' );
    ok( -f "$dir/$new_id.job.json", 'new job recorded' );
}

# --- ownership report jobs -------------------------------------------------------------------
is(
    $Cpanel::API::UserTools::API{ownership_report_start}{needs_feature},
    'usertools_ownership_report',
    '%API declares needs_feature for report start'
);
is(
    $Cpanel::API::UserTools::API{ownership_report_status}{needs_feature},
    'usertools_ownership_report',
    '%API declares needs_feature for report status'
);
is(
    $Cpanel::API::UserTools::API{ownership_report_cancel}{needs_feature},
    'usertools_ownership_report',
    '%API declares needs_feature for report cancel'
);

sub report_make_home {
    my $home = make_home();
    make_path("$home/public_html");
    open my $fh, '>', "$home/public_html/index.html" or die $!;
    print $fh "x\n";
    close $fh;
    return $home;
}

sub report_start {
    my ( $home, %params ) = @_;
    $params{scope} = 'public_html' unless exists $params{scope};
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::ownership_report_start( FakeArgs->new(%params), $res );
    return ( $ok, $res );
}

sub report_wait_done {
    my ($job_id) = @_;
    for ( 1 .. 200 ) {
        my $res = FakeResult->new();
        my $ok = Cpanel::API::UserTools::ownership_report_status(
            FakeArgs->new( job_id => $job_id ), $res );
        if ( $ok && $res->{data}{state} eq 'done' ) {
            return $res;
        }
        select( undef, undef, undef, 0.1 );
    }
    die "report job $job_id did not finish";
}

{
    my $home = report_make_home();
    my ( $ok, $res ) = report_start($home);
    ok( $ok, 'report start accepted' );
    like( $res->{data}{job_id}, qr/^report-/, 'report job id shape' );
    my $st = report_wait_done( $res->{data}{job_id} );
    my $summary = $st->{data}{summary};
    is( $summary->{command}, 'report', 'engine ran the report command' );
    ok( exists $summary->{not_owned_by}, 'grouped owners present' );
    is( $st->{data}{user}, 'testuser', 'status carries the username' );
}

{
    # Report summary shape (grouping itself is covered by engine unit tests
    # with fake uids; a mapping cannot cross into the spawned engine here).
    my $home = report_make_home();
    my ( $ok, $res ) = report_start($home);
    ok( $ok, 'report start accepted' );
    my $st = report_wait_done( $res->{data}{job_id} );
    my $summary = $st->{data}{summary};
    is( ref $summary->{not_owned_by}, 'HASH', 'owner groups hash present' );
    is( ref $summary->{paths}{not_owned}, 'ARRAY', 'not-owned list present' );
    is( $summary->{counts}{changed}, 0, 'report never changes modes' );
}

{
    # Cancel + unknown job paths.
    my $home = report_make_home();
    my $res  = FakeResult->new();
    my $ok = Cpanel::API::UserTools::ownership_report_status(
        FakeArgs->new( job_id => 'report-nope' ), $res );
    ok( !$ok, 'unknown report job refused' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::ownership_report_cancel(
        FakeArgs->new( job_id => 'report-nope' ), $res );
    ok( !$ok, 'unknown report cancel refused' );
}

# --- CSV rules (Perl mirror of the usertools.js builders) -------------------------------
# No JS runtime exists in this environment, so the exact escaping and
# formula-injection rules are pinned here AND asserted present in the
# shipped usertools.js below. The page builds CSV client-side from these.
sub csv_cell {
    my ($s) = @_;
    $s = '' unless defined $s;
    if ( $s =~ /^[=+\-@\t\r]/ ) {
        $s = "'$s";
    }
    if ( $s =~ /[",\n\r]/ ) {
        $s =~ s/"/""/g;
        return "\"$s\"";
    }
    return $s;
}

{
    is( csv_cell('plain'),             'plain',   'plain cell untouched' );
    is( csv_cell('a,b'),               '"a,b"',   'comma triggers quotes' );
    is( csv_cell('say "hi"'),          '"say ""hi"""', 'quotes doubled' );
    is( csv_cell("a\nb"),              "\"a\nb\"", 'newline triggers quotes' );
    is( csv_cell('=cmd'),              "'=cmd",   'formula = prefixed' );
    is( csv_cell('+cmd'),              "'+cmd",   'formula + prefixed' );
    is( csv_cell('-cmd'),              "'-cmd",   'formula - prefixed' );
    is( csv_cell('@cmd'), q{'@cmd}, 'formula @ prefixed' );
    is( csv_cell("\tcmd"),   "'\tcmd",   'formula tab prefixed' );
    is( csv_cell("\rcmd"),   "\"'\rcmd\"", 'formula CR prefixed, then quoted' );
    is( csv_cell('a-b'),               'a-b',     'mid-string dash untouched' );
    is( csv_cell('=a,b'),              "\"'=a,b\"", 'prefixed then quoted' );
    is( csv_cell(''),                  '',        'empty stays empty' );
    is( csv_cell(undef),               '',        'undef becomes empty' );
    is( csv_cell('/home/u/.ssh/x'),    '/home/u/.ssh/x', 'paths untouched' );
}

{
    # The shipped JS implements the same rules (checked textually: no JS
    # engine is available to execute it here).
    open my $fh, '<', "$FindBin::Bin/../frontend/shared/assets/usertools.js"
      or die "cannot read usertools.js: $!";
    local $/;
    my $js = <$fh>;
    close $fh;
    like( $js, qr{\Q/^[=+\-@\t\r]/\E}, 'JS has the formula-guard pattern' );
    like( $js, qr{replace\(/"/g, '""'\)}, 'JS doubles quotes' );
    ok( $js =~ /csvCell: csvCell/, 'csvCell helper exported' );
    ok( $js =~ /buildCsv: buildCsv/, 'buildCsv helper exported' );
    ok( $js =~ /topDirs: topDirs/, 'topDirs helper exported' );
}

# --- manage shell UAPI wrappers ------------------------------------------------------------------
is(
    $Cpanel::API::UserTools::API{shell_status}{needs_feature},
    'usertools_shell',
    '%API declares needs_feature for shell status'
);
is(
    $Cpanel::API::UserTools::API{shell_set}{needs_feature},
    'usertools_shell',
    '%API declares needs_feature for shell set'
);

{
    my $home = make_home();
    make_path("$home/.ssh");
    open my $fh, '>', "$home/.ssh/authorized_keys" or die $!;
    print $fh "# comment\n\nssh-ed25519 AAAATEST user\@host\n";
    close $fh;
    Cpanel::AdminBin::Call::reset();
    $Cpanel::AdminBin::Call::RESPOND{GET_SHELL} = {
        mode => 'jailed', shell_path => '/usr/local/cpanel/bin/jailshell',
        allowed_modes => [qw(disabled jailed)], normal_allowed => 0,
        ssh_port => '2222',
        ssh_login_blocked => { blocked => 1, reason => 'denyusers' },
    };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::shell_status( FakeArgs->new(), $res );
    ok( $ok, 'shell_status accepted' );
    is( $res->{data}{mode}, 'jailed', 'admin mode passed through' );
    is( $res->{data}{user}, 'testuser', 'username added' );
    is( $res->{data}{has_authorized_keys}, 1, 'key detected' );
    is_deeply( $res->{data}{ssh_login_blocked}, { blocked => 1, reason => 'denyusers' },
        'blocked object passed through, no raw name lists' );
    is( $Cpanel::AdminBin::Call::CALLS[0]{action}, 'GET_SHELL', 'called GET_SHELL' );
    is( $Cpanel::AdminBin::Call::CALLS[0]{ns}, 'UserTools', 'admin namespace' );
    is( $Cpanel::AdminBin::Call::CALLS[0]{mod}, 'Shell', 'admin module' );
}

{
    my $home = make_home();    # no .ssh here
    Cpanel::AdminBin::Call::reset();
    $Cpanel::AdminBin::Call::RESPOND{GET_SHELL} = { mode => 'disabled' };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::shell_status( FakeArgs->new(), $res );
    ok( $ok, 'status without keys accepted' );
    is( $res->{data}{has_authorized_keys}, 0, 'missing keys reported' );

    make_path("$home/.ssh");
    symlink "$home/public_html", "$home/.ssh/authorized_keys";
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::shell_status( FakeArgs->new(), $res );
    ok( $ok, 'status with symlinked keys accepted' );
    is( $res->{data}{has_authorized_keys}, 0, 'symlinked keys count as none' );
}

{
    my $home = make_home();
    Cpanel::AdminBin::Call::reset();
    $Cpanel::AdminBin::Call::RESPOND{SET_SHELL} = { mode => 'jailed' };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::shell_set(
        FakeArgs->new( mode => 'jailed', user => 'root', username => 'x' ), $res );
    ok( $ok, 'shell_set accepted' );
    is( scalar(@Cpanel::AdminBin::Call::CALLS), 1, 'one admin call' );
    is_deeply( $Cpanel::AdminBin::Call::CALLS[0]{args}, [{ mode => 'jailed' }],
        'exactly {mode} forwarded; user=/username= dropped' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::shell_set( FakeArgs->new( mode => 'turbo' ), $res );
    ok( !$ok, 'bad mode refused before the admin call' );
    is( scalar(@Cpanel::AdminBin::Call::CALLS), 1, 'no admin call for bad mode' );

    $Cpanel::AdminBin::Call::RESPOND{SET_SHELL} = { error => 'nope' };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::shell_set( FakeArgs->new( mode => 'jailed' ), $res );
    ok( !$ok, 'admin-side error surfaces' );

    $Cpanel::AdminBin::Call::RESPOND{SET_SHELL} = { error => 'Shell access is disabled by server policy.' };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::shell_set( FakeArgs->new( mode => 'jailed' ), $res );
    ok( !$ok, 'admin-side policy error surfaces' );
    unlike( $res->{errors}[0][1], qr/\.\z/, 'trailing period stripped before [_1]. so no double period' );
}

# --- Suspended account refuses at the adminbin transport ------------------------------------
{
    my $home = make_home();
    Cpanel::AdminBin::Call::reset();
    my $raw = 'Failed to parse adminbin request: UserTools::SET_SHELL::fetch is not allowed for suspended accounts at /usr/local/cpanel/Cpanel/AdminBin/Server.pm line 87.';

    $Cpanel::AdminBin::Call::RESPOND{SET_SHELL} = sub { die "$raw\n" };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::shell_set( FakeArgs->new( mode => 'jailed' ), $res );
    ok( !$ok, 'suspended shell_set refused (die shape)' );
    like( $res->{errors}[0][0], qr/Your account is suspended; shell changes are unavailable/,
        'die shape mapped to the suspension notice' );

    $Cpanel::AdminBin::Call::RESPOND{SET_SHELL} =
      { error => 'UserTools::SET_SHELL::fetch is not allowed for suspended accounts (Server.pm line 87)' };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::shell_set( FakeArgs->new( mode => 'jailed' ), $res );
    ok( !$ok, 'suspended shell_set refused (hash shape)' );
    like( $res->{errors}[0][0], qr/suspended/, 'hash shape mapped too' );

    $Cpanel::AdminBin::Call::RESPOND{GET_SHELL} = sub { die "$raw\n" };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::shell_status( FakeArgs->new(), $res );
    ok( !$ok, 'suspended shell_status refused' );
    like( $res->{errors}[0][0], qr/suspended/, 'status maps the die too' );

    $Cpanel::AdminBin::Call::RESPOND{SET_SHELL} = sub { die "boom at Server.pm line 1" };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::shell_set( FakeArgs->new( mode => 'jailed' ), $res );
    ok( !$ok, 'non-suspension die still refused' );
    is( $res->{errors}[0][0], 'Shell change error: [_1].', 'generic die keeps the maketext pattern' );
    like( $res->{errors}[0][1], qr/boom/, 'generic die text surfaced' );
    Cpanel::AdminBin::Call::reset();
}

# --- app helper: %API ---------------------------------------------------------------------------
for my $fn (qw(app_helper_list app_helper_add app_helper_remove
  app_helper_artisan app_helper_fix_perms app_helper_env_check
  app_helper_docroot_preview app_helper_set_docroot app_helper_undo_docroot
  app_helper_htaccess_preview app_helper_htaccess_apply app_helper_htaccess_undo
  app_helper_primary_check app_helper_primary_set
  app_helper_deploy_info app_helper_composer_start app_helper_npm_start
  app_helper_deploy_status app_helper_deploy_cancel
  app_helper_logs app_helper_log_view app_helper_log_clear
  app_helper_maintenance app_helper_cron_status app_helper_cron_add
  app_helper_cron_remove app_helper_readiness app_helper_production_preview
  app_helper_production_apply app_helper_production_undo
  app_helper_key_generate)) {
    is( $Cpanel::API::UserTools::API{$fn}{needs_feature},
        'usertools_app_helper', "%API declares needs_feature for $fn" );
}

# --- Raw_error takes exactly one literal -------------------------------------------
# Cpanel::Result::raw_error has signature ($self, $text) on 11.138 (perl
# signatures): placeholder messages must go through error($msg, @args).
sub _balanced_args {
    my ( $src, $pos ) = @_;
    my $depth = 1;
    my $quote = '';
    my $i     = $pos;
    my $len   = length($src);
    my $end   = $len;
    while ( $i < $len ) {
        my $c = substr( $src, $i, 1 );
        if ( $quote ne '' ) {
            if ( $c eq '\\' ) {
                $i += 2;
                next;
            }
            if ( $c eq $quote ) {
                $quote = '';
            }
        }
        elsif ( $c eq "'" || $c eq '"' ) {
            $quote = $c;
        }
        elsif ( $c eq '#' ) {
            $i++ while $i < $len && substr( $src, $i, 1 ) ne "\n";
            next;
        }
        elsif ( $c eq '(' ) {
            $depth++;
        }
        elsif ( $c eq ')' ) {
            $depth--;
            if ( $depth == 0 ) {
                $end = $i + 1;
                last;
            }
        }
        $i++;
    }
    return ( substr( $src, $pos, $end - $pos - 1 ), $end );
}

sub _split_top_level {
    my ($args) = @_;
    my @parts;
    my ( $depth, $quote, $cur ) = ( 0, '', '' );
    my $i   = 0;
    my $len = length($args);
    while ( $i < $len ) {
        my $c = substr( $args, $i, 1 );
        if ( $quote ne '' ) {
            $cur .= $c;
            if ( $c eq '\\' && $i + 1 < $len ) {
                $cur .= substr( $args, $i + 1, 1 );
                $i += 2;
                next;
            }
            if ( $c eq $quote ) {
                $quote = '';
            }
        }
        elsif ( $c eq "'" || $c eq '"' ) {
            $quote = $c;
            $cur .= $c;
        }
        elsif ( $c eq '(' ) {
            $depth++;
            $cur .= $c;
        }
        elsif ( $c eq ')' ) {
            $depth--;
            $cur .= $c;
        }
        elsif ( $c eq ',' && $depth == 0 ) {
            push @parts, $cur;
            $cur = '';
        }
        else {
            $cur .= $c;
        }
        $i++;
    }
    push @parts, $cur;
    return @parts;
}

{
    open my $fh, '<', "$FindBin::Bin/../Cpanel/API/UserTools.pm" or die $!;
    local $/;
    my $src = <$fh>;
    close $fh;
    my @bad;
    while ( $src =~ /->raw_error\s*\(/g ) {
        my ( $args, $end ) = _balanced_args( $src, pos($src) );
        my @parts = _split_top_level($args);
        if ( @parts > 1 ) {
            ( my $short = $args ) =~ s/\s+/ /g;
            push @bad, substr( $short, 0, 80 );
        }
        pos($src) = $end;
    }
    is_deeply( \@bad, [], 'no multi-arg raw_error calls' );
}

# --- app helper fixtures -----------------------------------------------------------------------
$Cpanel::API::UserTools::TEST_ENGINE_BIN = 'python3';
$Cpanel::API::UserTools::TEST_ENGINE    = "$FindBin::Bin/../engine/perm_engine.py";
$ENV{USERTOOLS_TESTING} = '1';

sub make_app_home {
    my $home = make_home();
    make_path("$home/myapp/vendor");
    make_path("$home/myapp/public");
    make_path("$home/myapp/storage/app/public");
    make_path("$home/myapp/bootstrap/cache");
    open my $fh, '>', "$home/myapp/artisan" or die $!;
    print $fh "#!/usr/bin/env php\n";
    close $fh;
    open my $af, '>', "$home/myapp/vendor/autoload.php" or die $!;
    print $af "<?php\n";
    close $af;
    open my $cf, '>', "$home/myapp/composer.json" or die $!;
    print $cf '{"name":"acme/app","require":{"php":">=8.1","laravel/framework":"^10.0"}}';
    close $cf;
    open my $lf, '>', "$home/myapp/composer.lock" or die $!;
    print $lf '{"packages":[{"name":"laravel/framework","version":"v10.20.0"}]}';
    close $lf;
    open my $ef, '>', "$home/myapp/.env" or die $!;
    print $ef "APP_NAME=Acme\nAPP_KEY=base64:xyz\n";
    close $ef;
    return $home;
}

sub make_fake_php {
    my ($dir) = @_;
    make_path("$dir/opt/cpanel/ea-php82/root/usr/bin");
    my $bin = "$dir/opt/cpanel/ea-php82/root/usr/bin/php";
    open my $fh, '>', "$bin" or die $!;
    print $fh <<'SCRIPT';
#!/bin/bash
# Conf dir sits next to the SCRIPT argument — the first arg containing a
# '/', because CLI flags like -d / -d key=value may precede it.
confdir="."
for a in "$@"; do case "$a" in */*) confdir="$(dirname "$a")"; break;; esac; done
conf="$confdir/.fakephp"
mkdir -p "$conf"
[ -f "$conf/sleep" ] && sleep "$(cat "$conf/sleep")"
printf 'ARGV:%s\n' "$@" >>"$conf/argv.log"
env | LC_ALL=C sort >>"$conf/env.log"
echo "---run---" >>"$conf/count.log"
[ -f "$conf/big" ] && head -c 100000 /dev/zero | tr '\0' x
if [ -f "$conf/out" ]; then cat "$conf/out"; else printf 'simulated artisan output'; fi
if [ -f "$conf/exit" ]; then exit "$(cat "$conf/exit")"; else exit 0; fi
SCRIPT
    close $fh;
    chmod 0755, $bin;
    return $bin;
}

sub fakephp_conf {
    # Write %kv into $approot/.fakephp/ (values are file contents; undef
    # deletes). Returns the conf dir for reading logs.
    my ( $approot, %kv ) = @_;
    my $conf = "$approot/.fakephp";
    make_path($conf);
    for my $k ( keys %kv ) {
        my $f = "$conf/$k";
        if ( !defined $kv{$k} ) {
            unlink $f;
            next;
        }
        open my $wfh, '>', $f or die $!;
        print $wfh $kv{$k};
        close $wfh;
    }
    return $conf;
}

sub fakephp_runs {
    my ($approot) = @_;
    open my $fh, '<', "$approot/.fakephp/count.log" or return 0;
    my @runs = <$fh>;
    close $fh;
    return scalar @runs;
}

sub fakephp_argv {
    my ($approot) = @_;
    open my $fh, '<', "$approot/.fakephp/argv.log" or die $!;
    my @argv = map { chomp; s/^ARGV://r } <$fh>;
    close $fh;
    return @argv;
}

# --- app_helper_list ------------------------------------------------------------------------------
{
    my $home = make_app_home();
    my $res  = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_list( FakeArgs->new(), $res );
    ok( $ok, 'list accepted' );
    my ($app) = grep { $_->{path} eq 'myapp' } @{ $res->{data}{apps} };
    ok( defined $app, 'detected app listed' );
    is( $app->{source},          'detected', 'source marked' );
    is( $app->{framework_version}, '10.20.0',  'version from lock' );
    is( $res->{data}{user},      'testuser', 'username present' );
}

# --- app_helper_list: per-app mapped domains --------------------------------------------------------------
{
    # Real 19-key DomainInfo shape; docroots map onto the apps.
    my $home = make_app_home();
    my $calls;
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        my ( $mod, $fn, $args ) = @_;
        $calls++;
        return {
            status => 1,
            data   => {
                main_domain   => make_domaininfo_rec( 'primary.test', "$home/public_html", 'main_domain', 'testuser' ),
                addon_domains => [ make_domaininfo_rec( 'app.test', "$home/myapp/public", 'addon_domain', 'testuser' ) ],
                sub_domains   => [ make_domaininfo_rec( 'sub.app.test', "$home/myapp/public", 'sub_domain', 'testuser' ) ],
            },
        };
    };
    my $res = FakeResult->new();
    my $ok  = Cpanel::API::UserTools::app_helper_list( FakeArgs->new(), $res );
    ok( $ok, 'list accepted with DomainInfo present' );
    my ($app) = grep { $_->{path} eq 'myapp' } @{ $res->{data}{apps} };
    is_deeply( $app->{domains}, [ 'app.test', 'sub.app.test' ], 'app row carries its mapped domains, sorted' );
    my @missing_domains = grep { !exists $_->{domains} } @{ $res->{data}{apps} };
    is( scalar(@missing_domains), 0, 'every app row carries the domains key' );
    is( $calls, 1, 'one domain enumeration for the whole list' );
}

{
    # Honest empty list when domains cannot be enumerated.
    my $home = make_app_home();
    make_path("$home/userdata/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = "$home/userdata";
    my $res = FakeResult->new();
    my $ok  = Cpanel::API::UserTools::app_helper_list( FakeArgs->new(), $res );
    ok( $ok, 'list accepted when domains cannot be listed' );
    my ($app) = grep { $_->{path} eq 'myapp' } @{ $res->{data}{apps} };
    is_deeply( $app->{domains}, [], 'empty domains list on enumeration failure' );
}

# --- manual add/remove + cap ---------------------------------------------------------------------------
{
    my $home = make_app_home();
    make_path("$home/plain");
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => 'plain' ), $res );
    ok( $ok, 'manual folder added' );
    is( $res->{data}{path}, 'plain', 'normalized path returned' );
    ok( -f "$home/.cpanel/usertools/apps.json", 'apps.json written' );
    is( ( stat("$home/.cpanel/usertools/apps.json") )[2] & 07777, 0600, 'apps.json is 0600' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_list( FakeArgs->new(), $res );
    my ($added) = grep { $_->{path} eq 'plain' } @{ $res->{data}{apps} };
    ok( defined $added && $added->{source} eq 'added', 'added folder listed' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => 'myapp' ), $res );
    ok( !$ok, 'already-detected folder refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => '../../etc' ), $res );
    ok( !$ok, 'traversal refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => '/abs' ), $res );
    ok( !$ok, 'absolute path refused' );

    make_path("$home/.ssh/evil");
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => '.ssh/evil' ), $res );
    ok( !$ok, 'protected path refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_remove( FakeArgs->new( path => 'plain' ), $res );
    ok( $ok, 'remove accepted' );
    is( scalar( @{ Cpanel::API::UserTools::_read_added_apps($home) } ), 0, 'list empty again' );
}

{
    my $home = make_app_home();
    for my $i ( 1 .. 20 ) {
        make_path("$home/d$i");
        my $res = FakeResult->new();
        my $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => "d$i" ), $res );
        ok( $ok, "add $i accepted" ) if $i == 20;
    }
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => 'd21' ), $res );
    make_path("$home/d21");
    ( $ok ) = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => 'd21' ), $res );
    ok( !$ok, '21st manual folder refused (cap 20)' );
}

# --- artisan: enum, injection, re-validation ----------------------------------------------------------------
{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;

    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear --force' ), $res );
    ok( !$ok, 'command with smuggled flag refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear;rm -rf ~' ), $res );
    ok( !$ok, 'command injection refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => '../../etc', command => 'cache:clear' ), $res );
    ok( !$ok, 'traversal app refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new(
            app => 'myapp', command => 'cache:clear', extra => 'x', user => 'root',
            php_version => 'ea-php82'
        ),
        $res
    );
    ok( $ok, 'extra keys ignored, valid call accepted' );
    is( $res->{data}{ok}, 1, 'artisan succeeded' );
    my @argv = fakephp_argv("$home/myapp");
    is( scalar(@argv), 2, 'exactly artisan + command reached PHP' );
    like( $argv[1], qr/^cache:clear$/, 'no injected arguments' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear', php_version => 'ea-php82;rm' ), $res );
    ok( !$ok, 'php_version injection refused' );

    # App deleted after listing: re-validation refuses.
    rename "$home/myapp", "$home/myapp-gone" or die $!;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( !$ok, 'vanished app refused' );
    rename "$home/myapp-gone", "$home/myapp" or die $!;
}

# --- artisan: PHP selection -----------------------------------------------------------------------------------
{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    my $php = "$home/phpbin/opt/cpanel/ea-php82/root/usr/bin/php";
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;

    my ($bin, $err) = Cpanel::API::UserTools::_select_php_bin('ea-php82');
    is( $bin, $php, 'explicit version resolves' );

    ( $bin, $err ) = Cpanel::API::UserTools::_select_php_bin('ea-php82;rm -rf ~');
    ok( !defined $bin, 'version injection rejected' );

    ( $bin, $err ) = Cpanel::API::UserTools::_select_php_bin('ea-php74');
    ok( !defined $bin, 'missing binary rejected' );

    my $fh74;
    open $fh74, '>', "$home/phpbin/opt/cpanel/ea-php74/root/usr/bin/php" or do {
        make_path("$home/phpbin/opt/cpanel/ea-php74/root/usr/bin");
        open $fh74, '>', "$home/phpbin/opt/cpanel/ea-php74/root/usr/bin/php" or die $!;
    };
    print $fh74 "#!/bin/sh\n";
    close $fh74;
    chmod 0644, "$home/phpbin/opt/cpanel/ea-php74/root/usr/bin/php";
    ( $bin, $err ) = Cpanel::API::UserTools::_select_php_bin('ea-php74');
    ok( !defined $bin, 'non-executable binary rejected' );

    ( $bin, $err ) = Cpanel::API::UserTools::_select_php_bin(undef);
    is( $bin, $php, 'default picks newest available' );
}

# --- artisan: timeout, cap, env, lock ------------------------------------------------------------------------------
{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";

    local $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 2;
    fakephp_conf("$home/myapp", sleep => "5");
    my $res = FakeResult->new();
    my $t0 = time();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    my $dt = time() - $t0;
    ok( $ok, 'timed-out call still returns' );
    is( $res->{data}{timed_out}, 1, 'timeout reported' );
    ok( $dt < 30, 'killed promptly, not after sleep' );
}

{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    fakephp_conf("$home/myapp", big => "");
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'big-output call returns' );
    is( $res->{data}{truncated}, 1, 'output capped' );
    is( length( $res->{data}{output} ), 65536, 'cap is 64 KiB' );
}

{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    local $ENV{USERTOOLS_SENTINEL} = 'should-not-pass';
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'env probe call accepted' );
    open my $efh, '<', "$home/myapp/.fakephp/env.log" or die $!;
    my @env = map { chomp; $_ } <$efh>;
    close $efh;
    my %seen = map { ( split /=/, $_, 2 )[0] => $_ } @env;
    is( $seen{PATH}, 'PATH=/usr/local/bin:/usr/bin:/bin', 'PATH allowlisted' );
    is( $seen{HOME}, "HOME=$home", 'HOME is the caller home' );
    is( $seen{LANG}, 'LANG=C.UTF-8', 'LANG passed' );
    ok( !exists $seen{USERTOOLS_SENTINEL}, 'parent env does not leak through' );
    delete $ENV{USERTOOLS_SENTINEL};
}

{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    make_path("$home/.cpanel/usertools");
    open my $lfh, '>>', Cpanel::API::UserTools::_artisan_lock_path( $home, 'myapp' ) or die $!;
    use Fcntl qw(:flock);
    flock( $lfh, LOCK_EX ) or die $!;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'locked call returns (not an error)' );
    is( $res->{data}{friendly}, 'busy', 'second job refused while locked' );
    is( fakephp_runs("$home/myapp"), 0, 'locked-out run never spawns PHP' );
    close $lfh;
}

# --- storage:link fallback ----------------------------------------------------------------------------------
{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    fakephp_conf("$home/myapp", exit => "1", out => 'symlink() has been disabled for security reasons');
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    unlink "$home/myapp/.env";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'storage:link' ), $res );
    ok( $ok, 'fallback call returns' );
    is( $res->{data}{fallback}{created}, 1, 'link created by fallback' );
    is( readlink("$home/myapp/public/storage"), '../storage/app/public', 'link is relative and correct' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'storage:link' ), $res );
    is( $res->{data}{fallback}{created}, 0, 'existing target never replaced' );
    like( $res->{data}{fallback}{detail}, qr/already exists/, 'refusal explained' );
}

{
    my $home = make_app_home();
    rename "$home/myapp/storage", "$home/myapp/storage-real" or die $!;
    symlink "$home/myapp/storage-real", "$home/myapp/storage" or die $!;
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    fakephp_conf("$home/myapp", exit => "1", out => 'symlink() has been disabled');
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    unlink "$home/myapp/.env";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'storage:link' ), $res );
    ok( $ok, 'fallback call returns' );
    is( $res->{data}{fallback}{created}, 0, 'symlinked storage/ refused' );
}

# --- friendly errors -----------------------------------------------------------------------------------------------
{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;

    make_path("$home/bare");
    open my $bf, '>', "$home/bare/artisan" or die $!;
    print $bf "#!/usr/bin/env php\n";
    close $bf;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => 'bare' ), $res );
    ok( $ok, 'bare folder added' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'bare', command => 'cache:clear' ), $res );
    ok( $ok, 'vendor check returns' );
    is( $res->{data}{friendly}, 'no_vendor', 'missing vendor is friendly' );
    is( fakephp_runs("$home/bare"), 0, 'nothing spawned for missing vendor' );

    unlink "$home/myapp/.env";
    fakephp_conf("$home/myapp", exit => "1", out => 'In Config.php line 1: wat');
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    is( $res->{data}{friendly}, 'no_app_key', 'missing APP_KEY is friendly' );

    open my $cjf, '>', "$home/myapp/composer.json" or die $!;
    print $cjf '{"require":{"php":">=99.0","laravel/framework":"^10.0"}}';
    close $cjf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear', php_version => 'ea-php82' ), $res );
    is( $res->{data}{friendly}, 'php_too_old', 'old PHP is friendly' );

    open my $cj2, '>', "$home/myapp/composer.json" or die $!;
    print $cj2 '{"require":{"php":">=8.1","laravel/framework":"^10.0"}}';
    close $cj2;
    open my $ef, '>', "$home/myapp/.env" or die $!;
    print $ef "APP_KEY=base64:xyz\n";
    close $ef;
    fakephp_conf("$home/myapp", out => 'file_put_contents: Permission denied');
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    is( $res->{data}{friendly}, 'permission', 'permission denied is friendly' );
}

# --- fix_perms preview + writability ------------------------------------------------------------------------------
{
    my $home = make_app_home();
    chmod 0600, "$home/myapp/artisan";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_fix_perms( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'fix_perms accepted' );
    is( $res->{data}{scope}, "$home/myapp", 'scope is the app root' );
    ok( ( $res->{data}{preview_counts}{would_change} // 0 ) >= 1, 'preview counts changes' );
    is( $res->{data}{storage}{writable},         1, 'storage writable reported' );
    is( $res->{data}{bootstrap_cache}{writable}, 1, 'bootstrap/cache writable reported' );
    is( ( stat("$home/myapp/artisan") )[2] & 07777, 0600, 'preview changed nothing' );
}

# --- _env_verdict unit mapping --------------------------------------------------------------------------------------
{
    my ( $v, $n );
    my $U = 'https://a/.env';
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 1, 200, "APP_KEY=base64:x\n", $U, 0 );
    is( "$v/$n", 'critical/', '200 with key is critical' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 1, 200, "hello\n", $U, 0 );
    is( "$v/$n", 'unknown/', '200 without key is unknown' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 0, 404, '', $U, 0 );
    is( "$v/$n", 'safe/', '404 is safe' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 0, 302, 'nothing here', $U, 0 );
    is( "$v/$n", 'safe/', 'redirect without key is safe' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 0, 302, 'x APP_KEY=y', $U, 0 );
    is( "$v/$n", 'critical/', 'redirect leaking key is critical' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 0, 599, '', $U, 0 );
    is( "$v/$n", 'unknown/could not verify (TLS)', 'TLS failure noted' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 1, 200, 'x' x 5000, $U, 0 );
    is( "$v/$n", 'unknown/', 'complete keyless body is unknown' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 1, 200, "APP_KEY=x\n" . ( 'y' x 5000 ), $U, 1 );
    is( "$v/$n", 'critical/', 'capped large body starting with key is critical' );
    ( $v, $n ) = Cpanel::API::UserTools::_env_verdict( 1, 200, 'y' x 5000, $U, 1 );
    is( "$v/$n", 'unknown/response exceeded the read cap', 'capped keyless prefix is unknown, never critical' );
}

# --- env_check: only own domains are ever requested ----------------------------------------------------------
{
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $fh, '>', "$udir/testuser/own1" or die $!;
    print $fh "---\ndocumentroot: $home/myapp/public\n";
    close $fh;
    open my $gh, '>', "$udir/testuser/own2" or die $!;
    print $gh "---\ndocumentroot: $home/other\n";
    close $gh;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_env_check( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'env check accepted' );
    my @urls = map { $_->{url} } @{ $res->{data}{checked} };
    ok( @urls >= 1, 'own domains probed' );
    ok( !grep( { $_ !~ m{^https://(own1|own2)/} } @urls ), 'no foreign host ever requested' );
}

{
    # Docroot-above-app yields the extra sub-path probe (URLs only asserted).
    my $home = make_app_home();
    make_path("$home/sites/blog");
    rename "$home/myapp", "$home/sites/blog/myapp" or die $!;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $fh, '>', "$udir/testuser/shop" or die $!;
    print $fh "---\ndocumentroot: $home/sites/blog\n";
    close $fh;
    my $ares = FakeResult->new();
    Cpanel::API::UserTools::app_helper_add( FakeArgs->new( path => 'sites/blog/myapp' ), $ares );
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_env_check( FakeArgs->new( app => 'sites/blog/myapp' ), $res );
    ok( $ok, 'env check accepted' );
    my @urls = map { $_->{url} } @{ $res->{data}{checked} };
    is( scalar(@urls), 2, 'docroot URL plus sub-path URL' );
    ok( ( grep { m{^https://shop/myapp/\.env$} } @urls ) ? 1 : 0, 'sub-path probe present' );
}

{
    # Empty domain list: honest note, nothing checked.
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_env_check( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'env check accepted' );
    is_deeply( $res->{data}{checked}, [], 'nothing checked' );
    like( $res->{data}{note}, qr/cannot list/i, 'honest note' );
}

# --- _user_domains via in-process UAPI (real 11.138 shape) ---------------------------------------------
sub make_domaininfo_rec {
    my ( $domain, $docroot, $type, $user ) = @_;
    $type = 'main_domain' unless defined $type;
    $user = 'testuser'    unless defined $user;
    return {
        customlog             => [ { format => 'combined', target => "/etc/apache2/logs/domlogs/$domain" } ],
        documentroot          => $docroot,
        domain                => $domain,
        group                 => $user,
        hascgi                => 1,
        homedir               => "/home/$user",
        ip                    => '192.0.2.10',
        is_temporary          => 0,
        owner                 => 'root',
        phpopenbasedirprotect => 1,
        port                  => '80',
        scriptalias           => [ { path => "/home/$user/public_html/cgi-bin", url => '/cgi-bin/' } ],
        serveradmin           => "webmaster\@$domain",
        serveralias           => "mail.$domain www.$domain",
        servername            => $domain,
        status                => '',
        type                  => $type,
        usecanonicalname      => 'Off',
        user                  => $user,
    };
}

{
    my $home = make_app_home();
    my @calls;
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        my ( $mod, $fn, $args ) = @_;
        push @calls, [ $mod, $fn, $args ];
        is_deeply( $args, {}, 'no parameters travel (caller identity is the process)' );
        return {
            status => 1,
            data   => {
                main_domain    => make_domaininfo_rec( 'a.test', '/home/u/a', 'main_domain', 'uttest' ),
                addon_domains  => [ make_domaininfo_rec( 'addon.test', '/home/u/addon', 'addon_domain', 'uttest' ) ],
                sub_domains    => [ { domain => 'b.test' } ],
                parked_domains => [ make_domaininfo_rec( 'parked.test', '/home/u/a', 'parked_domain', 'uttest' ) ],
            },
        };
    };
    my ( $recs, $main ) = Cpanel::API::UserTools::_user_domain_info('uttest');
    is( $main, 'a.test', 'main_domain hash parsed to primary domain name' );
    my %by_dom = map { $_->{domain} => $_ } @{$recs};
    is( scalar( keys %by_dom ), 3, 'main + addon + parked records kept, incomplete sub skipped' );
    is( $by_dom{'a.test'}{kind},      'main',   'main_domain classified as main' );
    is( $by_dom{'addon.test'}{kind},  'addon',  'addon_domains classified as addon' );
    is( $by_dom{'parked.test'}{kind}, 'parked', 'parked_domains classified as parked' );

    @calls = ();
    my @domains = Cpanel::API::UserTools::_user_domains('uttest');
    is( scalar(@domains), 3, 'complete records returned by _user_domains' );
    is_deeply(
        \@calls,
        [ [ 'DomainInfo', 'domains_data', {} ] ],
        'in-process DomainInfo call, no CLI argv'
    );
}

# --- Userdata fallback skips cPanel's internal files ----------------------------------------------
{
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    for my $f (
        'main', 'main.cache', 'cache', 'cache.json',
        'shop.test', 'shop.test.cache', 'shop.test_SSL', 'shop.test_SSL.cache',
        'shop.test.php-fpm.yaml',
      )
    {
        open my $fh, '>', "$udir/testuser/$f" or die $!;
        print $fh "---\ndocumentroot: $home/public_html\n";
        close $fh;
    }
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    my @domains = Cpanel::API::UserTools::_user_domains_userdata('testuser');
    is_deeply(
        [ map { $_->{domain} } @domains ],
        ['shop.test'],
        'only the real domain file is listed'
    );
}

# --- Docroot boundary -------------------------------------------------------------------------------------
{
    ok( Cpanel::API::UserTools::_docroot_mapped( '/h/a', '/h/a' ), 'equal maps' );
    ok( Cpanel::API::UserTools::_docroot_mapped( '/h/a', '/h/a/b' ), 'app under docroot maps' );
    ok( Cpanel::API::UserTools::_docroot_mapped( '/h/a/b', '/h/a' ), 'docroot under app maps' );
    ok( !Cpanel::API::UserTools::_docroot_mapped( '/h/shopping', '/h/shop/app' ),
        'sibling prefix does not map' );
    ok( !Cpanel::API::UserTools::_docroot_mapped( '/h/other', '/h/a' ), 'unrelated does not map' );
    ok( !Cpanel::API::UserTools::_docroot_mapped( '', '/h/a' ), 'empty docroot does not map' );
}

# --- Mapped-only probing, 10-domain cap, time budget ---------------------------------------------
{
    # Fast-failing local names keep this deterministic (no DNS).
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $fh, '>', "$udir/testuser/localhost" or die $!;
    print $fh "---\ndocumentroot: $home/myapp/public\n";
    close $fh;
    open my $gh, '>', "$udir/testuser/127.0.0.1" or die $!;
    print $gh "---\ndocumentroot: $home/other\n";
    close $gh;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_env_check( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'env check accepted' );
    my @urls = map { $_->{url} } @{ $res->{data}{checked} };
    is( scalar(@urls), 1, 'only the mapped domain is probed' );
    like( $urls[0], qr{^https://localhost/}, 'mapped host probed' );
}

{
    # Cap: 12 mapped domains -> 10 checked, 2 deferred with the budget note.
    # HTTP is mocked (instant 404s) so this is deterministic with no network.
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    for my $i ( 1 .. 12 ) {
        open my $fh, '>', "$udir/testuser/d$i.example" or die $!;
        print $fh "---\ndocumentroot: $home/myapp/public\n";
        close $fh;
    }
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_env_check( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'env check accepted' );
    my @checked = @{ $res->{data}{checked} };
    is( scalar(@checked), 12, 'all domains accounted for' );
    my @deferred = grep { ( $_->{note} // '' ) eq 'not checked (time budget)' } @checked;
    is( scalar(@deferred), 2, 'two deferred past the cap of 10' );
    my @done = grep { ( $_->{note} // '' ) eq '' } @checked;
    is( scalar(@done), 10, 'ten actually checked' );
    is( $done[0]{verdict}, 'safe', 'mocked 404s are safe' );
}

{
    # Time budget seam: -1 defers everything without network use.
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    local $Cpanel::API::UserTools::TEST_ENV_BUDGET_SECONDS = -1;
    open my $fh, '>', "$udir/testuser/own" or die $!;
    print $fh "---\ndocumentroot: $home/myapp/public\n";
    close $fh;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_env_check( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'env check accepted' );
    is( scalar( @{ $res->{data}{checked} } ), 1, 'one entry' );
    is( $res->{data}{checked}[0]{note}, 'not checked (time budget)', 'budget deferral noted' );
}

# --- Server-side PHP default --------------------------------------------------------------------------------
{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    # Second installed version so default-vs-LangPHP choices differ.
    make_path("$home/phpbin/opt/cpanel/ea-php81/root/usr/bin");
    open my $fh, '>', "$home/phpbin/opt/cpanel/ea-php81/root/usr/bin/php" or die $!;
    print $fh "#!/bin/sh\nexit 0\n";
    close $fh;
    chmod 0755, "$home/phpbin/opt/cpanel/ea-php81/root/usr/bin/php";
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    my $langphp = { status => 1, data => [ { vhost => 'x', php_version => 'ea-php81' } ] };
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        my ( $mod, $fn, $args ) = @_;
        if ( $mod eq 'LangPHP' ) {
            return $langphp;
        }
        return {
            status => 1,
            data   => {
                main_domain    => make_domaininfo_rec( 'primary.test', "$home/public_html", 'main_domain' ),
                addon_domains  => [ make_domaininfo_rec( 'shop', "$home/myapp/public", 'addon_domain' ) ],
                sub_domains    => [],
                parked_domains => [],
            },
        };
    };
    fakephp_conf("$home/myapp");
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'artisan without version accepted' );
    like( $res->{data}{php_bin}, qr/ea-php81/, 'LangPHP version preferred over newest installed' );

    $langphp = { status => 1,
        data => [ { vhost => 'x', php_version => 'ea-php82' }, { vhost => 'y', php_version => 'ea-php81' } ] };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'artisan accepted' );
    like( $res->{data}{php_bin}, qr/ea-php82/, 'multi-version output falls back to newest installed' );

    $langphp = 'not json';
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'artisan accepted' );
    like( $res->{data}{php_bin}, qr/ea-php82/, 'broken LangPHP falls back to newest installed' );
}

# --- addon/subdomain docroot ------------------------------------------------------------------
sub make_docroot_home {
    # Laravel app + userdata records (addon 'shop', primary 'primary.test').
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    open my $fh, '>', "$udir/testuser/shop" or die $!;
    print $fh "---\ndocumentroot: $home/oldroot\n";
    close $fh;
    open my $mf, '>', "$udir/testuser/main" or die $!;
    print $mf "---\nmain_domain: primary.test\ndocumentroot: $home/public_html\n";
    close $mf;
    open my $pf, '>', "$udir/testuser/primary.test" or die $!;
    print $pf "---\ndocumentroot: $home/public_html\n";
    close $pf;
    return ( $home, $udir );
}

{
    my ( $home, $udir ) = make_docroot_home();
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_docroot_preview(
        FakeArgs->new( app => 'myapp', domain => 'shop' ), $res );
    ok( $ok, 'docroot preview accepted' );
    is( $res->{data}{old_docroot}, "$home/oldroot", 'old docroot shown' );
    is( $res->{data}{new_docroot}, "$home/myapp/public", 'new docroot is always app/public' );
    is( $res->{data}{allowed}, 1, 'allowed' );
}

{
    # Primary domain refused here (it has its own switch).
    my ( $home, $udir ) = make_docroot_home();
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_docroot_preview(
        FakeArgs->new( app => 'myapp', domain => 'primary.test' ), $res );
    ok( !$ok, 'primary refused' );
    like( $res->{errors}[0][1], qr/main-domain/, 'points at the main-domain switch' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_docroot_preview(
        FakeArgs->new( app => 'myapp', domain => 'evil.test' ), $res );
    ok( !$ok, 'foreign domain refused' );
    like( $res->{errors}[0][1], qr/unknown domain/, 'foreign domain message' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_docroot_preview(
        FakeArgs->new( app => 'myapp', domain => 'a/b' ), $res );
    ok( !$ok, 'malformed domain refused' );
}

{
    # Restrict tweak: app outside public_html is explained, not obscure.
    my ( $home, $udir ) = make_docroot_home();
    open my $cf, '>', "$home/cpanel.config" or die $!;
    print $cf "publichtmlsubsonly=1\n";
    close $cf;
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    local $Cpanel::API::UserTools::TEST_CPANEL_CONFIG = "$home/cpanel.config";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_docroot_preview(
        FakeArgs->new( app => 'myapp', domain => 'shop' ), $res );
    ok( $ok, 'preview accepted' );
    is( $res->{data}{allowed}, 0, 'not allowed under the tweak' );
    like( $res->{data}{reason}, qr/public_html/, 'reason explains the restriction' );

    # Same tweak, app under public_html: allowed.
    make_path("$home/public_html");
    rename "$home/myapp", "$home/public_html/myapp" or die $!;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_docroot_preview(
        FakeArgs->new( app => 'public_html/myapp', domain => 'shop' ), $res );
    ok( $ok, 'preview accepted' );
    is( $res->{data}{allowed}, 1, 'allowed under public_html' );
    is( $res->{data}{new_docroot}, "$home/public_html/myapp/public", 'new docroot under public_html' );
}

{
    # Set + undo round-trip; the args capture proves the documented
    # in-process call with the documented parameters.
    my ( $home, $udir ) = make_docroot_home();
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    my @calls;
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        my ( $mod, $fn, $args ) = @_;
        push @calls, [ $mod, $fn, $args ];
        if ( $mod eq 'DomainInfo' ) {
            return {
                status => 1,
                data   => {
                    main_domain    => make_domaininfo_rec( 'primary.test', "$home/public_html", 'main_domain' ),
                    addon_domains  => [ make_domaininfo_rec( 'shop', "$home/oldroot", 'addon_domain' ) ],
                    sub_domains    => [],
                    parked_domains => [],
                },
            };
        }
        return { status => 1, data => { documentroot => "$home/myapp/public" } };
    };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_set_docroot(
        FakeArgs->new( app => 'myapp', domain => 'shop' ), $res );
    ok( $ok, 'set accepted' );
    is( $res->{data}{new_docroot}, "$home/myapp/public", 'new docroot returned' );
    my ($change) = grep { $_->[0] eq 'SubDomain' } @calls;
    ok( defined $change, 'changedocroot called in-process' );
    is( $change->[1], 'changedocroot', 'official changedocroot function' );
    is_deeply( $change->[2], { domain => 'shop', docroot => 'myapp/public' },
        'documented domain+docroot params, home-relative, never user input' );
    my $jfile = "$home/.cpanel/usertools/docroot.json";
    ok( -f $jfile, 'undo journal written' );
    is( ( stat($jfile) )[2] & 07777, 0600, 'journal is 0600' );

    @calls = ();
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_undo_docroot( FakeArgs->new( domain => 'shop' ), $res );
    ok( $ok, 'undo accepted' );
    is( $res->{data}{restored}, "$home/oldroot", 'previous docroot restored' );
    is_deeply( $calls[0][2], { domain => 'shop', docroot => 'oldroot' },
        'undo calls back with the stored docroot' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_undo_docroot( FakeArgs->new( domain => 'shop' ), $res );
    ok( !$ok, 'second undo refused' );
    like( $res->{errors}[0][0], qr/Nothing to undo/, 'nothing-to-undo message' );
}

{
    # Server-side failure passes through honestly.
    my ( $home, $udir ) = make_docroot_home();
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        return { status => 0, errors => ['docroot outside public_html'] };
    };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_set_docroot(
        FakeArgs->new( app => 'myapp', domain => 'shop' ), $res );
    ok( !$ok, 'server failure refused' );
    like( $res->{errors}[0][1], qr/outside public_html/, 'server reason passed through' );
}

# --- .htaccess generator --------------------------------------------------------------------
{
    # Preview defaults: non-www, trailing slash, expires/deflate on.
    my $home = make_app_home();
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_preview(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'htaccess preview accepted' );
    my $pub = $res->{data}{public};
    like( $pub->{new}, qr/Require all granted/, 'public grants' );
    like( $pub->{new}, qr/RewriteRule \^ index\.php/, 'front controller present' );
    like( $pub->{new}, qr/REQUEST_SCHEME/, 'non-www default on' );
    like( $pub->{new}, qr/mod_deflate/, 'expires/deflate default on' );
    unlike( $pub->{new}, qr/HTTPS.*off/, 'force-https default off' );
    unlike( $pub->{new}, qr/HTTP_AUTHORIZATION/, 'auth passthrough default off' );
    like( $res->{data}{root}{new}, qr/Require all denied/, 'root denies' );
    is( $res->{data}{options}{nonwww}, 1, 'default recorded' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_preview(
        FakeArgs->new( app => 'myapp', https => '1', auth => '1', sitemap => '1' ), $res );
    ok( $ok, 'htaccess preview accepted' );
    like( $res->{data}{public}{new}, qr/HTTPS\} off/, 'force-https on request' );
    like( $res->{data}{public}{new}, qr/HTTP_AUTHORIZATION/, 'auth on request' );
    like( $res->{data}{public}{new}, qr/sitemap/, 'sitemap on request' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_preview(
        FakeArgs->new( app => 'myapp', https => 'yes' ), $res );
    ok( !$ok, 'bad option refused' );
}

{
    # Merge: cPanel blocks + user lines preserved byte-for-byte, in order.
    my $cpanel = "# php -- BEGIN cPanel-generated handler, do not edit\nAddType application/x-httpd-ea-php82 .php\n# php -- END cPanel-generated handler, do not edit\n";
    my $current = $cpanel . "\n# my own rule\nRedirect 302 /old /new\n";
    my $block = "Require all granted\n";
    my $merged = Cpanel::API::UserTools::_ht_merge( $current, $block );
    is( index( $merged, $cpanel ), 0, 'cPanel block first and verbatim' );
    like( $merged, qr/# my own rule\nRedirect 302 \/old \/new\n/, 'user lines kept' );
    like( $merged, qr/# BEGIN UserTools\nRequire all granted\n# END UserTools\n/, 'our block appended' );
    my $again = Cpanel::API::UserTools::_ht_merge( $merged, $block );
    is( $again, $merged, 're-apply is idempotent' );
    my $n_begin = () = $merged =~ /# BEGIN UserTools/g;
    is( $n_begin, 1, 'exactly one marked block' );
}

{
    # Weak patterns from the three real-world variants.
    my $vendor = "<FilesMatch \"^(vendor/|composer\\.lock)\">\nRequire all denied\n</FilesMatch>\n";
    my $w = Cpanel::API::UserTools::_htaccess_warnings( 'root', $vendor );
    ok( ( grep { /vendor/ } @{$w} ) ? 1 : 0, 'vendor FilesMatch warned' );
    my $serve = "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} -f\nRewriteRule ^ - [L]\n";
    $w = Cpanel::API::UserTools::_htaccess_warnings( 'root', $serve );
    ok( ( grep { /serves existing/ } @{$w} ) ? 1 : 0, 'serve-existing rewrite warned' );
    my $topublic = 'RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(.*)$ /public/$1 [L]
';
    $w = Cpanel::API::UserTools::_htaccess_warnings( 'root', $topublic );
    ok( ( grep { /rewrites into public/ } @{$w} ) ? 1 : 0, 'root-to-public rewrite warned' );
    $w = Cpanel::API::UserTools::_htaccess_warnings( 'root', "Options -Indexes\nRequire all denied\n" );
    is_deeply( $w, [], 'safe template is quiet' );
}

{
    # Apply + undo round-trip with mocked HTTP (instant 404s, healthy homepage).
    my $home = make_app_home();
    open my $rf, '>', "$home/myapp/.htaccess" or die $!;
    print $rf "# php -- BEGIN cPanel-generated handler, do not edit\nX\n# php -- END cPanel-generated handler, do not edit\n";
    close $rf;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{restored}, 0, 'healthy homepage: no auto-restore' );
    open my $pf, '<', "$home/myapp/public/.htaccess" or die $!;
    my $pub = do { local $/; <$pf> };
    close $pf;
    like( $pub, qr/Require all granted/, 'public file written' );
    is( ( stat("$home/myapp/public/.htaccess") )[2] & 07777, 0644, 'public file is 0644' );
    open my $qf, '<', "$home/myapp/.htaccess" or die $!;
    my $root = do { local $/; <$qf> };
    close $qf;
    like( $root, qr/cPanel-generated handler/, 'cPanel block survived apply' );
    like( $root, qr/Require all denied/, 'root denies' );
    my @baks = glob "$home/myapp/.htaccess.usertools-bak-*";
    is( scalar(@baks), 1, 'root backup kept' );
    is( ( stat( $baks[0] ) )[2] & 07777, 0600, 'backup is 0600' );

    for ( 1 .. 5 ) {
        $res = FakeResult->new();
        $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
            FakeArgs->new( app => 'myapp' ), $res );
        ok( $ok, 're-apply accepted' );
    }
    @baks = glob "$home/myapp/.htaccess.usertools-bak-*";
    is( scalar(@baks), 3, 'only the last 3 backups kept' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_undo(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'undo accepted' );
    is( $res->{data}{root}, 'original', 'root restored from the preserved original' );
    open my $uf, '<', "$home/myapp/.htaccess" or die $!;
    my $restored = do { local $/; <$uf> };
    close $uf;
    like( $restored, qr/cPanel-generated handler/, 'a kept backup state is back' );
    my $jfile = "$home/.cpanel/usertools/htaccess.json";
    ok( -f $jfile, 'originals journal written' );
    is( ( stat($jfile) )[2] & 07777, 0600, 'originals journal is 0600' );
}

{
    # Single apply then undo: exact original bytes return.
    my $home = make_app_home();
    my $orig = "# php -- BEGIN cPanel-generated handler, do not edit\nX\n# php -- END cPanel-generated handler, do not edit\n";
    open my $rf, '>', "$home/myapp/.htaccess" or die $!;
    print $rf $orig;
    close $rf;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_undo(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'undo accepted' );
    open my $uf, '<', "$home/myapp/.htaccess" or die $!;
    my $restored = do { local $/; <$uf> };
    close $uf;
    is( $restored, $orig, 'original bytes back after undo' );
    unlike( $restored, qr/BEGIN UserTools/, 'our block gone after undo' );
    ok( !-f "$home/myapp/public/.htaccess", 'created public file removed by undo' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_undo(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'second undo falls back to the kept rolling backup' );
    is( $res->{data}{root}, 'backup', 'backup fallback reported' );
}

{
    # Undo with no history at all is refused honestly.
    my $home = make_app_home();
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_undo(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( !$ok, 'undo with no history refused' );
    like( $res->{errors}[0][0], qr/Nothing to undo/, 'nothing-to-undo message' );
}

{
    # Auto-restore when the homepage breaks (mocked 403): both files return.
    my $home = make_app_home();
    open my $rf, '>', "$home/myapp/.htaccess" or die $!;
    print $rf "# before\n";
    close $rf;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 403; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{restored}, 1, 'broken homepage triggers auto-restore' );
    like( $res->{data}{reason}, qr/403/, 'reason names the status' );
    open my $qf, '<', "$home/myapp/.htaccess" or die $!;
    my $root = do { local $/; <$qf> };
    close $qf;
    is( $root, "# before\n", 'root file restored byte-for-byte' );
    ok( !-f "$home/myapp/public/.htaccess", 'created public file removed' );
}

# --- primary-domain switch (user side) ------------------------------------------------------
sub make_public_html_app {
    # App living directly in public_html/ (the primary-domain case).
    my $home = make_home();
    make_path("$home/public_html/vendor");
    make_path("$home/public_html/public");
    make_path("$home/public_html/storage/app/public");
    make_path("$home/public_html/bootstrap/cache");
    open my $fh, '>', "$home/public_html/artisan" or die $!;
    print $fh "#!/usr/bin/env php\n";
    close $fh;
    open my $af, '>', "$home/public_html/vendor/autoload.php" or die $!;
    print $af "<?php\n";
    close $af;
    open my $cf, '>', "$home/public_html/composer.json" or die $!;
    print $cf '{"name":"acme/app","require":{"php":">=8.1","laravel/framework":"^10.0"}}';
    close $cf;
    open my $lf, '>', "$home/public_html/composer.lock" or die $!;
    print $lf '{"packages":[{"name":"laravel/framework","version":"v10.20.0"}]}';
    close $lf;
    open my $ix, '>', "$home/public_html/public/index.php" or die $!;
    print $ix "<?php // front\n";
    close $ix;
    return $home;
}

sub write_ht_pair {
    my ($home) = @_;
    ( my $re = "$home/public_html/public" ) =~ s/\./\\./g;
    open my $rf, '>', "$home/public_html/.htaccess" or die $!;
    print $rf "# BEGIN UserTools\n"
        . "<If \"%{REQUEST_FILENAME} !~ m#^$re(/|\$)#\">\n"
        . "Require all denied\n</If>\n# END UserTools\n";
    close $rf;
    open my $pf, '>', "$home/public_html/public/.htaccess" or die $!;
    print $pf "# BEGIN UserTools\nRequire all granted\n# END UserTools\n";
    close $pf;
    return;
}

{
    my $home = make_public_html_app();
    write_ht_pair($home);
    open my $pf, '>', "$home/policy.conf" or die $!;
    print $pf "allow_user_app_docroot=1\n";
    close $pf;
    local $Cpanel::API::UserTools::TEST_POLICY_FILE = "$home/policy.conf";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_primary_check(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'primary check accepted' );
    is( $res->{data}{eligible}, 1, 'eligible' );
    is( $res->{data}{policy_allowed}, 1, 'policy allows' );
    like( $res->{data}{host_command},
        qr/whmapi1 set_primary_domain_docroot username=testuser docroot=public_html\/public/,
        'copy-ready host command' );

    Cpanel::AdminBin::Call::reset();
    $Cpanel::AdminBin::Call::RESPOND{SET_APP_DOCROOT} = { enable => 1, docroot => 'public_html/public', changed => 0 };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '1' ), $res );
    ok( $ok, 'primary set accepted' );
    is( $Cpanel::AdminBin::Call::CALLS[0]{action}, 'SET_APP_DOCROOT', 'called SET_APP_DOCROOT' );
    is( $Cpanel::AdminBin::Call::CALLS[0]{mod}, 'AppDocroot', 'admin module' );
    is_deeply( $Cpanel::AdminBin::Call::CALLS[0]{args}, [ { enable => 1 } ],
        'boolean enable passed, nothing else' );
    is( $res->{data}{changed}, 0, 'changed flag passed through to the caller' );
    Cpanel::AdminBin::Call::reset();

    # The suspended-account refusal arrives as a transport die.
    $Cpanel::AdminBin::Call::RESPOND{SET_APP_DOCROOT} = sub {
        die "Failed to parse adminbin request: UserTools::SET_APP_DOCROOT::fetch is not allowed for suspended accounts at /usr/local/cpanel/Cpanel/AdminBin/Server.pm line 87.\n";
    };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '1' ), $res );
    ok( !$ok, 'suspended primary_set refused (die shape)' );
    like( $res->{errors}[0][0], qr/Your account is suspended; main-domain changes are unavailable/,
        'die shape mapped to the suspension notice' );

    $Cpanel::AdminBin::Call::RESPOND{SET_APP_DOCROOT} =
      { error => 'UserTools::SET_APP_DOCROOT::fetch is not allowed for suspended accounts (Server.pm line 87)' };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '1' ), $res );
    ok( !$ok, 'suspended primary_set refused (hash shape)' );
    like( $res->{errors}[0][0], qr/suspended/, 'hash shape mapped too' );
    Cpanel::AdminBin::Call::reset();

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '2' ), $res );
    ok( !$ok, 'non-boolean enable refused before the admin call' );
}

{
    # Readiness refusals: wrong folder, missing index, missing htaccess pair.
    my $home = make_app_home();
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_primary_check(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'primary check accepted' );
    is( $res->{data}{eligible}, 0, 'nested app not eligible' );
    like( $res->{data}{reason}, qr/directly in public_html/, 'reason names the layout' );

    $home = make_public_html_app();
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_check(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'primary check accepted' );
    is( $res->{data}{eligible}, 0, 'missing pair not eligible' );
    like( $res->{data}{reason}, qr/htaccess/i, 'reason names the htaccess pair' );

    unlink "$home/public_html/public/index.php";
    write_ht_pair($home);
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '1' ), $res );
    ok( !$ok, 'missing index refused before the admin call' );
    like( $res->{errors}[0][1], qr/index\.php/, 'reason names index.php' );
}

{
    # The account-creation hook writes marker-only files, a later apply
    # records them as the originals, and undo used to restore the root
    # lock verbatim — refusing enable=0 forever. Undo must now strip our
    # block from the restored original (deleting a file that held nothing
    # else), and lock detection reads the live file only.
    my $home = make_public_html_app();
    write_ht_pair($home);    # exactly what the hook leaves behind
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/primary.test" or die $!;
    print $df "---\ndocumentroot: $home/public_html/public\n";
    close $df;
    open my $mf, '>', "$udir/testuser/main" or die $!;
    print $mf "main_domain: primary.test\n";
    close $mf;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };

    # A later apply preserves the hook files as originals.
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'apply accepted over the hook-written pair' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_undo(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'undo accepted' );
    is( $res->{data}{root}, 'removed',
        'restored lock-only original leaves no file' );
    is( $res->{data}{public}, 'removed',
        'restored lock-only public original leaves no file' );
    ok( !-f "$home/public_html/.htaccess", 'no root .htaccess after undo' );
    ok( !-f "$home/public_html/public/.htaccess", 'no public .htaccess after undo' );

    # Lock detection sees the live file only, and the revert stays offered.
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_check(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'primary check accepted' );
    is( $res->{data}{lock}, 0, 'no lock after undo' );
    is( $res->{data}{eligible}, 1,
        'revert still offered (the domain serves public/)' );

    Cpanel::AdminBin::Call::reset();
    $Cpanel::AdminBin::Call::RESPOND{SET_APP_DOCROOT} = { enable => 0, docroot => 'public_html' };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '0' ), $res );
    ok( $ok, 'primary_set enable=0 succeeds once the lock is gone' );
    is_deeply( $Cpanel::AdminBin::Call::CALLS[0]{args}, [ { enable => 0 } ],
        'enable=0 passed to the admin module' );
    Cpanel::AdminBin::Call::reset();
}

{
    # Originals the USER wrote (no markers anywhere) restore
    # byte-for-byte on both files, with their own labels untouched.
    my $home = make_app_home();
    my $root_orig = "# my own rules\nRewriteEngine On\n";
    my $pub_orig  = "Options -Indexes\n# user note\n";
    open my $rf, '>', "$home/myapp/.htaccess" or die $!;
    print $rf $root_orig;
    close $rf;
    open my $pf, '>', "$home/myapp/public/.htaccess" or die $!;
    print $pf $pub_orig;
    close $pf;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted with user originals on both files' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_undo(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'undo accepted' );
    is( $res->{data}{root}, 'original', 'root labelled original' );
    is( $res->{data}{public}, 'original', 'public labelled original' );
    open my $ur, '<', "$home/myapp/.htaccess" or die $!;
    my $root_now = do { local $/; <$ur> };
    close $ur;
    is( $root_now, $root_orig, 'user root bytes identical' );
    open my $up, '<', "$home/myapp/public/.htaccess" or die $!;
    my $pub_now = do { local $/; <$up> };
    close $up;
    is( $pub_now, $pub_orig, 'user public bytes identical' );
}

# --- nested domains skip the root file ---------------------------------------------------
{
    # App at public_html, addon docroot at public_html/shop: the root deny
    # would 403 the shop, so only the public file is written.
    my $home = make_public_html_app();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop2" or die $!;
    print $df "---\ndocumentroot: $home/public_html/shop\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_preview(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'preview accepted' );
    is( $res->{data}{root_skipped}, 1, 'root skipped with a nested domain' );
    is_deeply( $res->{data}{nested_domains}, ['shop2'], 'nested list returned' );
    like( $res->{data}{root_note}, qr/would be blocked/, 'plain-text explanation' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{root_skipped}, 1, 'apply skips the root file' );
    ok( !-f "$home/public_html/.htaccess", 'root file untouched' );
    ok( -f "$home/public_html/public/.htaccess", 'public file still written' );
    is( $res->{data}{backups}{root}, undef, 'no root backup' );
}

{
    # Same app, addon OUTSIDE it (~/shop.com): the root file is written.
    my $home = make_public_html_app();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop.com" or die $!;
    print $df "---\ndocumentroot: $home/shop.com\n";
    close $df;
    make_path("$home/shop.com");
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{root_skipped}, 0, 'root not skipped' );
    is( $res->{data}{root_deferred}, 0, 'root not deferred' );
    open my $rf, '<', "$home/public_html/.htaccess" or die $!;
    my $root = do { local $/; <$rf> };
    close $rf;
    like( $root, qr/Require all denied/, 'root deny written' );
}

# --- docroot-aware apply ---------------------------------------------------------------
{
    # Primary at public_html: apply defers the root, the switch succeeds,
    # apply again locks the root.
    my $home = make_public_html_app();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/primary.test" or die $!;
    print $df "---\ndocumentroot: $home/public_html\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'first apply accepted' );
    is( $res->{data}{root_deferred}, 1, 'root deferred while the domain is on the app root' );
    like( $res->{data}{root_note}, qr/public folder first/, 'deferral explains the order' );
    is( $res->{data}{restored}, 0, 'no auto-restore on deferral' );
    ok( -f "$home/public_html/public/.htaccess", 'public file written' );
    ok( !-f "$home/public_html/.htaccess", 'root file untouched' );

    Cpanel::AdminBin::Call::reset();
    $Cpanel::AdminBin::Call::RESPOND{SET_APP_DOCROOT} = { enable => 1, docroot => 'public_html/public' };
    open my $pf, '>', "$home/policy.conf" or die $!;
    print $pf "allow_user_app_docroot=1\n";
    close $pf;
    local $Cpanel::API::UserTools::TEST_POLICY_FILE = "$home/policy.conf";
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '1' ), $res );
    ok( $ok, 'the switch succeeds on the public file alone' );
    Cpanel::AdminBin::Call::reset();

    open my $uf, '>', "$udir/testuser/primary.test" or die $!;
    print $uf "---\ndocumentroot: $home/public_html/public\n";
    close $uf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'public_html' ), $res );
    ok( $ok, 'second apply accepted' );
    is( $res->{data}{root_deferred}, 0, 'no longer deferred' );
    open my $rf, '<', "$home/public_html/.htaccess" or die $!;
    my $root = do { local $/; <$rf> };
    close $rf;
    like( $root, qr/Require all denied/, 'root locked after the switch' );
    is( $res->{data}{restored}, 0, 'healthy guard: no restore' );
}

{
    # Addon equivalent: domain on the app root defers, pointing it at
    # public/ unlocks the root file.
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        return { status => 1, data => {} };
    };
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{root_deferred}, 1, 'deferred while the addon is on the app root' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_set_docroot(
        FakeArgs->new( app => 'myapp', domain => 'shop' ), $res );
    ok( $ok, 'addon pointed at public/' );
    open my $uf, '>', "$udir/testuser/shop" or die $!;
    print $uf "---\ndocumentroot: $home/myapp/public\n";
    close $uf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{root_deferred}, 0, 'no longer deferred' );
    open my $rf, '<', "$home/myapp/.htaccess" or die $!;
    my $root = do { local $/; <$rf> };
    close $rf;
    like( $root, qr/Require all denied/, 'root locked after pointing' );
}

# --- only real failures restore --------------------------------------------------------
{
    # The real probe against a closed local port: 599/0, never a down signal.
    my $st = Cpanel::API::UserTools::_http_head_status('https://127.0.0.1:9/');
    ok( $st == 599 || $st == 0, 'closed port reports 599/0' );
    ok( !Cpanel::API::UserTools::_is_down_status($st), 'connection failure never restores' );
    ok( Cpanel::API::UserTools::_is_down_status(403), '403 restores' );
    ok( Cpanel::API::UserTools::_is_down_status(500), '500 restores' );
    ok( Cpanel::API::UserTools::_is_down_status(598), '598 restores' );
    ok( !Cpanel::API::UserTools::_is_down_status(599), '599 never restores' );
    ok( !Cpanel::API::UserTools::_is_down_status(0), '0 never restores' );
    ok( !Cpanel::API::UserTools::_is_down_status(301), '301 never restores' );
    ok( !Cpanel::API::UserTools::_is_down_status(200), '200 never restores' );
}

{
    # A 301 homepage (e.g. www non-www redirect, guard follows nothing)
    # counts as OK.
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 301; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp', nonwww => '1' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{restored}, 0, '301 homepage does not restore' );
}

# --- the original always survives -------------------------------------------------------
{
    # A stale backup from an earlier apply is never used by auto-restore:
    # this apply made no backups, so the planted file must be untouched.
    my $home = make_app_home();
    open my $sf, '>', "$home/myapp/public/.htaccess.usertools-bak-0" or die $!;
    print $sf "STALE\n";
    close $sf;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 500; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{restored}, 1, 'real 500 restores' );
    open my $cf, '<', "$home/myapp/public/.htaccess.usertools-bak-0" or die $!;
    my $stale = do { local $/; <$cf> };
    close $cf;
    is( $stale, "STALE\n", 'stale backup untouched' );
    ok( !-f "$home/myapp/public/.htaccess", 'created file removed, not "restored" from stale' );
}

# --- the mapped domain's PHP wins -------------------------------------------------------
{
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    make_path("$home/phpbin/opt/cpanel/ea-php81/root/usr/bin");
    open my $fh, '>', "$home/phpbin/opt/cpanel/ea-php81/root/usr/bin/php" or die $!;
    print $fh "#!/bin/sh\nexit 0\n";
    close $fh;
    chmod 0755, "$home/phpbin/opt/cpanel/ea-php81/root/usr/bin/php";
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    my $langphp = { status => 1,
        data => [
            { domain => 'shop', php_version => 'ea-php81' },
            { domain => 'other', php_version => 'ea-php82' },
        ] };
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        my ( $mod, $fn, $args ) = @_;
        if ( $mod eq 'LangPHP' ) {
            return $langphp;
        }
        return {
            status => 1,
            data   => {
                main_domain    => make_domaininfo_rec( 'primary.test', "$home/public_html", 'main_domain' ),
                addon_domains  => [ make_domaininfo_rec( 'shop', "$home/myapp/public", 'addon_domain' ) ],
                sub_domains    => [],
                parked_domains => [],
            },
        };
    };
    fakephp_conf("$home/myapp");
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'artisan without version accepted' );
    like( $res->{data}{php_bin}, qr/ea-php81/, 'mapped domain version wins over account mix' );

    $langphp = { status => 1, data => [ { domain => 'other', php_version => 'ea-php82' } ] };
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'artisan accepted' );
    like( $res->{data}{php_bin}, qr/ea-php82/, 'unmapped version falls back to account-wide single' );
}

# --- Blessed Cpanel::Result handling ----------------------------------------------------------------
package FakeAPIResult;
sub new {
    my ( $class, $status, $errors_ar, $data_hr ) = @_;
    return bless {
        _status => $status, _errors => $errors_ar // [], _data => $data_hr // {},
    }, $class;
}
sub status { return $_[0]->{_status}; }
sub errors { return $_[0]->{_errors}; }
sub data   { return $_[0]->{_data}; }

package main;

{
    # Blessed result object: success and failure through methods.
    my ( $home, $udir ) = make_docroot_home();
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        my ( $mod, $fn, $args ) = @_;
        if ( $mod eq 'DomainInfo' ) {
            return FakeAPIResult->new(
                1, [],
                {
                    main_domain    => make_domaininfo_rec( 'primary.test', "$home/public_html", 'main_domain' ),
                    addon_domains  => [ make_domaininfo_rec( 'shop', "$home/oldroot", 'addon_domain' ) ],
                    sub_domains    => [],
                    parked_domains => [],
                }
            );
        }
        return FakeAPIResult->new( 1, [], { documentroot => "$home/myapp/public" } );
    };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_set_docroot(
        FakeArgs->new( app => 'myapp', domain => 'shop' ), $res );
    ok( $ok, 'blessed success accepted' );
    is( $res->{data}{new_docroot}, "$home/myapp/public", 'new docroot returned' );
}

{
    my ( $home, $udir ) = make_docroot_home();
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    no warnings 'redefine';
    local *Cpanel::API::execute = sub {
        my ( $mod, $fn, $args ) = @_;
        if ( $mod eq 'DomainInfo' ) {
            return FakeAPIResult->new(
                1, [],
                {
                    main_domain    => make_domaininfo_rec( 'primary.test', "$home/public_html", 'main_domain' ),
                    addon_domains  => [ make_domaininfo_rec( 'shop', "$home/oldroot", 'addon_domain' ) ],
                    sub_domains    => [],
                    parked_domains => [],
                }
            );
        }
        return FakeAPIResult->new( 0, ['docroot outside public_html'] );
    };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_set_docroot(
        FakeArgs->new( app => 'myapp', domain => 'shop' ), $res );
    ok( !$ok, 'blessed failure refused' );
    like( $res->{errors}[0][1], qr/outside public_html/, 'method reason passed through' );
}

{
    # Anything else is unreadable, never a success.
    my ( $st, $reason ) = Cpanel::API::UserTools::_uapi_result_status('garbage');
    ok( !defined $st, 'string result is unreadable' );
    ( $st, $reason ) = Cpanel::API::UserTools::_uapi_result_status(undef);
    ok( !defined $st, 'undef result is unreadable' );
    ( $st, $reason ) = Cpanel::API::UserTools::_uapi_result_status( bless {}, 'Weird' );
    ok( !defined $st, 'methodless object is unreadable' );
    ( $st, $reason ) = Cpanel::API::UserTools::_uapi_result_status( { status => 1 } );
    is( $st, 1, 'plain hash still works' );
}

# --- CloudLinux --------------------------------------------------------------------
{
    # alt-php tier: newest alt-php between mapped ea-php and the default.
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    make_path("$home/altbin/php81/usr/bin");
    make_path("$home/altbin/php82/usr/bin");
    for my $v (qw(81 82)) {
        open my $fh, '>', "$home/altbin/php$v/usr/bin/php" or die $!;
        print $fh "#!/bin/sh\nexit 0\n";
        close $fh;
        chmod 0755, "$home/altbin/php$v/usr/bin/php";
    }
    local $Cpanel::API::UserTools::TEST_ALT_PHP_DIR = "$home/altbin";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    fakephp_conf("$home/myapp");
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'artisan accepted' );
    like( $res->{data}{php_bin}, qr{/altbin/php82/usr/bin/php}, 'newest alt-php wins over ea-php default' );
    is( $res->{data}{php_source}, 'alt-php', 'source reported for Details' );

    my ( $bin, $err ) = Cpanel::API::UserTools::_select_alt_php_bin();
    like( $bin, qr/php82/, 'resolver picks newest' );
    ok( Cpanel::API::UserTools::_php_bin_allowed($bin), 'resolver output is allowlisted' );
    ok( !Cpanel::API::UserTools::_php_bin_allowed('/tmp/evil/php'), 'stray paths refused' );
    ok( !Cpanel::API::UserTools::_php_bin_allowed('/opt/cpanel/ea-php82/root/usr/bin/php;rm'), 'metachars refused' );
    ok( Cpanel::API::UserTools::_php_bin_allowed('/opt/cpanel/ea-php82/root/usr/bin/php'), 'ea-php allowed' );
    ok( Cpanel::API::UserTools::_php_bin_allowed('/usr/local/bin/php'), 'system php allowed' );
}

{
    # Node.js resolvers: ea-nodejs first, then alt-nodejs, newest each.
    # CG5: CloudLinux layout is root/usr/bin (not bin/).
    my $home = make_home();
    make_path("$home/cpanel/ea-nodejs18/bin");
    make_path("$home/cpanel/ea-nodejs20/bin");
    make_path("$home/alt/alt-nodejs14/root/usr/bin");
    for my $p (qw(cpanel/ea-nodejs18 cpanel/ea-nodejs20)) {
        open my $fh, '>', "$home/$p/bin/node" or die $!;
        print $fh "#!/bin/sh\nexit 0\n";
        close $fh;
        chmod 0755, "$home/$p/bin/node";
    }
    open my $fh, '>', "$home/alt/alt-nodejs14/root/usr/bin/node" or die $!;
    print $fh "#!/bin/sh\nexit 0\n";
    close $fh;
    chmod 0755, "$home/alt/alt-nodejs14/root/usr/bin/node";
    my ( $bin, $src ) = Cpanel::API::UserTools::_select_nodejs_bin( "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs20/, 'newest ea-nodejs wins' );
    is( $src, 'ea-nodejs', 'source named' );
    ( $bin, $src ) = Cpanel::API::UserTools::_select_nodejs_bin( "$home/empty", "$home/alt" );
    like( $bin, qr/alt-nodejs14/, 'CG5: alt-nodejs fallback at root/usr/bin' );
    like( $bin, qr{root/usr/bin/node$}, 'CG5: alt layout used' );
    is( $src, 'alt-nodejs', 'source named' );
    my ( $nobin, $reason ) = Cpanel::API::UserTools::_select_nodejs_bin( "$home/empty", "$home/empty2" );
    ok( !defined $nobin, 'nothing found' );
}

{
    # _select_node_for_app finds the alt layout, and the PATH fix
    # prepends that bin folder (so env-node resolves inside the cage).
    my $home = make_home();
    make_path("$home/alt/alt-nodejs24/root/usr/bin");
    for my $n (qw(node npm)) {
        open my $fh, '>', "$home/alt/alt-nodejs24/root/usr/bin/$n" or die $!;
        print $fh "#!/bin/sh\nexit 0\n";
        close $fh;
        chmod 0755, "$home/alt/alt-nodejs24/root/usr/bin/$n";
    }
    my $app = "$home/app";
    make_path($app);
    my ( $bin, $src, $warn ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/empty", "$home/alt" );
    like( $bin, qr{alt-nodejs24/root/usr/bin/node$}, 'CG5: app resolver uses alt layout' );
    ( my $npm = $bin ) =~ s{/bin/node$}{/bin/npm};
    ok( -x $npm, 'CG5: npm sits next to node' );
    my $r = Cpanel::API::UserTools::_deploy_recipe_npm(
        $home, $app, $npm, 0 );
    like( $r->{steps}[0]{env}{PATH},
        qr{^\Q$home\E/alt/alt-nodejs24/root/usr/bin:},
        'PATH prepends the selected alt bin dir' );
}

{
    # LVE hints: signals and limit signatures guide, everything else is quiet.
    is( Cpanel::API::UserTools::_lve_hint( { exit => 0, output => 'ok' } ), undef, 'clean run: no hint' );    like( Cpanel::API::UserTools::_lve_hint( { exit => 0, output => '', signaled => 1 } ),
        qr/resource limit/, 'signal death hinted' );
    like( Cpanel::API::UserTools::_lve_hint( { exit => 255, output => "PHP Fatal error: Cannot allocate memory\n" } ),
        qr/out of memory|resource limit/, 'OOM hinted' );
    like( Cpanel::API::UserTools::_lve_hint( { exit => 1, output => 'fork: Resource temporarily unavailable' } ),
        qr/process or file limit/, 'fork failure hinted' );
    # CG6: exit 137 (OOM-killer/LVE SIGKILL) hints even with no output text.
    like( Cpanel::API::UserTools::_lve_hint( { exit => 137, output => '' } ),
        qr/out of memory|resource limit/, 'CG6: exit 137 hinted' );
    like( Cpanel::API::UserTools::_lve_hint( { exit => -9, output => '' } ),
        qr/out of memory|resource limit/, 'CG6: SIGKILL hinted' );

    # Overall recipe budget comes from the public policy (default 3600).
    my $pdir = tempdir( CLEANUP => 1 );
    my $pconf = "$pdir/policy.conf";
    open my $pf, '>', $pconf or die $!;
    print $pf "max_job_seconds=120\n";
    close $pf;
    local $Cpanel::API::UserTools::TEST_POLICY_FILE = $pconf;
    is( Cpanel::API::UserTools::_policy_max_job_seconds(), 120, 'policy budget read' );
    open my $qf, '>', $pconf or die $!;
    print $qf "max_job_seconds=lots\n";
    close $qf;
    is( Cpanel::API::UserTools::_policy_max_job_seconds(), 3600, 'garbage budget falls back' );

    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    fakephp_conf( "$home/myapp", out => "Cannot allocate memory\n" );
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_artisan(
        FakeArgs->new( app => 'myapp', command => 'cache:clear' ), $res );
    ok( $ok, 'artisan accepted' );
    like( $res->{data}{resource_hint} // '', qr/resource limit/, 'hint travels with the result' );

    # CG6: deploy LVE hint — exit 137 or memory fault says so in plain words.
    is( Cpanel::API::UserTools::_deploy_lve_hint(
            { ok => 0, steps => [ { name => 'npm run build', exit => 137 } ] }, '' ),
        'Your account hit its memory limit while building; ask your host or build locally',
        'CG6: exit 137 says memory limit in plain words' );
    is( Cpanel::API::UserTools::_deploy_lve_hint(
            { ok => 0, steps => [ { name => 'composer install', exit => 1 } ] },
            "PHP Fatal error: Allowed memory size exhausted\n" ),
        'Your account hit its memory limit while building; ask your host or build locally',
        'CG6: memory fault says memory limit in plain words' );
    is( Cpanel::API::UserTools::_deploy_lve_hint(
            { ok => 0, steps => [ { name => 'npm run build', exit => 1 } ] }, 'ok' ),
        undef, 'CG6: ordinary failure has no LVE hint' );
}

{
    # The generator never emits php_value/php_flag (handler-dependent).
    my ( $opt, $err ) = Cpanel::API::UserTools::_ht_options( FakeArgs->new() );
    ok( defined $opt, 'default options parse' );
    my $pub = Cpanel::API::UserTools::_ht_public_block( %{$opt} );
    unlike( $pub, qr/php_value|php_flag/i, 'no handler directives generated' );
    my $full = Cpanel::API::UserTools::_ht_public_block(
        %{$opt}, https => 1, auth => 1, sitemap => 1, indexphp => 1 );
    unlike( $full, qr/php_value|php_flag/i, 'no handler directives with all options' );
}

# --- exempting root lock ----------------------------------------------------------------
{
    # Exact escaped path rendering.
    my ( $block, $err ) = Cpanel::API::UserTools::_ht_root_block_for('/home/u.name/my-app_1/public');
    ok( defined $block, 'safe path accepted' );
    like( $block, qr/m#\^\/home\/u\\.name\/my-app_1\/public\(\/\|\$\)#/,
        'exemption path exact and dot-escaped' );
    like( $block, qr/Require all denied/, 'deny retained' );

    for my $bad ( '/home/u;rm', '/home/u#x', '/home/u x', '/home/u$x', '' ) {
        ( $block, $err ) = Cpanel::API::UserTools::_ht_root_block_for($bad);
        ok( !defined $block, "unsafe path refused: [$bad]" );
    }
}

{
    # The exemption uses the vhost-configured string, not the realpath.
    # Home reached through a symlink: realpath and docroot differ.
    my $base = tempdir( CLEANUP => 1 );
    make_path("$base/real/home/myapp/public");
    symlink( "$base/real", "$base/link" ) or die $!;
    my $home    = "$base/link/home";
    my $approot = "$home/myapp";
    my $udir    = "$base/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $approot/public\n";
    close $df;
    my $plan = Cpanel::API::UserTools::_ht_root_state( 'testuser', $home, $approot );
    ok( $plan->{write_root}, 'planned' );
    like( $plan->{block}, qr/\Q$approot\E\/public/, 'DomainInfo string used' );
    my $real = Cwd::realpath($approot);
    ok( $real ne $approot, 'fixture really diverges' );
    unlike( $plan->{block}, qr/\Q$real\E/, 'realpath not used' );
}

{
    # No mapped domain on public/ -> getpwnam home + rel path.
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/elsewhere\n";
    close $df;
    no warnings 'redefine';
    local *CORE::GLOBAL::getpwnam = sub {
        my ($name) = @_;
        if ( $name eq 'testuser' ) {
            return ( 'testuser', 'x', 1000, 1000, '', '', '', '/home2/testuser', '/bin/bash' );
        }
        return CORE::getpwnam($name);
    };
    my ( $exempt, $err ) =
      Cpanel::API::UserTools::_ht_exempt_public( 'testuser', $home, "$home/myapp" );
    is( $exempt, '/home2/testuser/myapp/public', 'getpwnam home + rel path, never realpath' );
}

{
    # Deploy overwrites public/.htaccess with stock: the list flags the
    # warning state while the lock still counts.
    my $home = make_app_home();
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    local *Cpanel::API::UserTools::_http_head_status = sub { return 200; };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_htaccess_apply(
        FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{root_deferred}, 0, 'root written (domain already on public/)' );

    open my $sf, '>', "$home/myapp/public/.htaccess" or die $!;
    print $sf "<IfModule mod_rewrite.c>\n    RewriteEngine On\n    RewriteRule ^ index.php [L]\n</IfModule>\n";
    close $sf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_list( FakeArgs->new(), $res );
    ok( $ok, 'list accepted' );
    my ($app) = grep { $_->{path} eq 'myapp' } @{ $res->{data}{apps} };
    is( $app->{htaccess}{lock}, 1, 'lock still seen after deploy overwrite' );
    is( $app->{htaccess}{public}, 0, 'missing public marker flagged' );
    ok( Cpanel::API::UserTools::_htaccess_pair_applied("$home/myapp"), 'pair check sees the lock' );
}

{
    # Reverting to public_html while locked is refused.
    my $home = make_public_html_app();
    write_ht_pair($home);
    open my $pf, '>', "$home/policy.conf" or die $!;
    print $pf "allow_user_app_docroot=1\n";
    close $pf;
    local $Cpanel::API::UserTools::TEST_POLICY_FILE = "$home/policy.conf";
    Cpanel::AdminBin::Call::reset();
    $Cpanel::AdminBin::Call::RESPOND{SET_APP_DOCROOT} = { enable => 0, docroot => 'public_html' };
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_primary_set(
        FakeArgs->new( app => 'public_html', enable => '0' ), $res );
    ok( !$ok, 'revert while locked refused before the admin call' );
    like( $res->{errors}[0][1], qr/root lock/, 'reason names the lock' );
    is( scalar(@Cpanel::AdminBin::Call::CALLS), 0, 'admin never called' );
    Cpanel::AdminBin::Call::reset();
}

# --- recipes, binaries, engines -----------------------------------------------------------------
{
    # Composer recipe argv/env (unit, no spawn).
    my $r = Cpanel::API::UserTools::_deploy_recipe_composer(
        '/home/u', '/home/u/myapp', '/opt/cpanel/ea-php82/root/usr/bin/php',
        '/opt/cpanel/composer/bin/composer' );
    is_deeply(
        $r->{steps}[0]{argv},
        [ '/opt/cpanel/ea-php82/root/usr/bin/php', '-d', 'allow_url_fopen=1',
            '/opt/cpanel/composer/bin/composer',
            'install', '--no-dev', '--optimize-autoloader', '--no-interaction',
            '--no-ansi', '--no-progress' ],
        'composer recipe argv asks for no colour/progress' );
    my @argv = @{ $r->{steps}[0]{argv} };
    is( scalar @argv, 10, 'flat argv list, nothing concatenated' );
    is( $argv[1], '-d', '-d goes to the PHP process, before the composer script' );
    is( $argv[2], 'allow_url_fopen=1', 'separate argv element, never shell-joined' );
    is( $argv[3], '/opt/cpanel/composer/bin/composer', 'composer script follows the -d pair' );
    ok( !( grep { /\s/ } @argv ), 'no element contains a shell fragment' );
    my $recipe_json = JSON::PP->new()->encode($r);
    unlike( $recipe_json, qr/php\.ini/, 'no php.ini anywhere in the recipe' );
    unlike( $recipe_json, qr/ini_dir|ini_set/, 'no ini manipulation anywhere in the recipe' );
    is( $r->{steps}[0]{env}{COMPOSER_HOME}, '/home/u/.cache/usertools/composer', 'composer home set' );
    unlike( $r->{steps}[0]{env}{COMPOSER_HOME}, qr{^/tmp}, 'never /tmp' );
    is( $r->{steps}[0]{cwd}, '/home/u/myapp', 'cwd is the app' );

    # npm recipe argv/env + node_modules removal step.
    my $napp = make_app_home() . '/myapp';
    $r = Cpanel::API::UserTools::_deploy_recipe_npm(
        '/home/u', $napp, '/opt/cpanel/ea-nodejs20/bin/npm', 0 );
    is( $r->{installer}, 'install', 'no lockfile means npm install' );
    is_deeply( $r->{steps}[0]{argv},
        [ '/opt/cpanel/ea-nodejs20/bin/npm', 'install', '--no-audit', '--no-fund' ],
        'install argv' );
    is_deeply( $r->{steps}[1]{argv}, [ '/opt/cpanel/ea-nodejs20/bin/npm', 'run', 'build' ], 'build second' );
    is_deeply( $r->{steps}[2]{argv}, [ '/bin/rm', '-rf', 'node_modules' ], 'cleanup last on success path' );
    ok( defined $r->{on_failure}, 'failure cleanup scheduled' );
    is_deeply( $r->{on_failure}{argv}, [ '/bin/rm', '-rf', 'node_modules' ], 'cleanup removes node_modules' );
    is( $r->{steps}[0]{env}{PATH},
        '/opt/cpanel/ea-nodejs20/bin:/usr/local/bin:/usr/bin:/bin',
        'selected node bin dir first on PATH' );
    is( $r->{steps}[0]{env}{NODE_COMPILE_CACHE},
        '/home/u/.cache/usertools/node-compile-cache', 'compile cache in account' );
    is( $r->{steps}[0]{env}{TMPDIR}, '/home/u/.cache/usertools/tmp', 'TMPDIR in account' );
    unlike( $r->{steps}[0]{env}{TMPDIR}, qr{^/tmp}, 'never /tmp' );
    is( $r->{steps}[0]{env}{npm_config_cache}, '/home/u/.cache/usertools/npm', 'npm cache set' );
    $r = Cpanel::API::UserTools::_deploy_recipe_npm(
        '/home/u', $napp, '/opt/cpanel/ea-nodejs20/bin/npm', 1 );
    is( scalar( @{ $r->{steps} } ), 2, 'keep skips the success-path cleanup' );
    ok( !defined $r->{on_failure}, 'keep skips failure cleanup too' );
    open my $lf, '>', "$napp/package-lock.json" or die $!;
    print $lf '{"lockfileVersion":3}';
    close $lf;
    $r = Cpanel::API::UserTools::_deploy_recipe_npm(
        '/home/u', $napp, '/opt/cpanel/ea-nodejs20/bin/npm', 0 );
    is( $r->{installer}, 'ci', 'lockfile means npm ci' );
    is_deeply( $r->{steps}[0]{argv}, [ '/opt/cpanel/ea-nodejs20/bin/npm', 'ci' ], 'npm ci first' );

    # Cache dirs are created 0700 and idempotent.
    my $chome = make_home();
    is( Cpanel::API::UserTools::_ensure_cache_dirs($chome), undef, 'cache dirs created' );
    is( ( CORE::lstat("$chome/.cache/usertools/tmp") )[2] & 07777, 0700, 'tmp is 0700' );
    is( ( CORE::lstat("$chome/.cache/usertools/node-compile-cache") )[2] & 07777,
        0700, 'node compile cache is 0700' );
    is( Cpanel::API::UserTools::_ensure_cache_dirs($chome), undef, 're-run is a no-op' );

    # Keep_node_modules validation fails fast on bad input.
    {
        my $khome = make_app_home();
        my $res = FakeResult->new();
        my $ok = Cpanel::API::UserTools::app_helper_npm_start(
            FakeArgs->new( app => 'myapp', keep_node_modules => 'sometimes' ), $res );
        ok( !$ok, 'bad keep flag refused' );
        like( $res->{errors}[0][0], qr/keep_node_modules/, 'refusal names the flag' );
    }
}

# --- Deploy_status reports what happened to node_modules ------------------------------
{
    sub write_deploy_job {
        my ( $home, $id, $meta_hr, $result_hr ) = @_;
        my $dir = "$home/.cpanel/usertools/jobs";
        make_path($dir);
        open my $mf, '>', "$dir/$id.job.json" or die $!;
        print $mf JSON::PP->new()->encode($meta_hr);
        close $mf;
        open my $rf, '>', "$dir/$id.result.json" or die $!;
        print $rf JSON::PP->new()->encode($result_hr);
        close $rf;
        return $id;
    }
    my $home = make_home();
    my $base_meta = { tool => 'deploy', id => 'deploy-nm1', pid => 1, recipe => 'npm_build' };
    write_deploy_job( $home, 'deploy-nm1', { %{$base_meta}, keep_node_modules => 1 },
        { ok => 1, steps => [] } );
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_deploy_status( FakeArgs->new( job_id => 'deploy-nm1' ), $res );
    ok( $ok, 'status accepted' );
    is( $res->{data}{node_modules}, 'kept', 'ticked keep reports kept' );
    write_deploy_job( $home, 'deploy-nm2', { %{$base_meta}, id => 'deploy-nm2', keep_node_modules => 0 },
        { ok => 0, cleanup => 'removed', steps => [ { name => 'npm run build', exit => 1 } ] } );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_deploy_status( FakeArgs->new( job_id => 'deploy-nm2' ), $res );
    ok( $ok, 'status accepted' );
    is( $res->{data}{state}, 'failed', 'failed state' );
    is( $res->{data}{node_modules}, 'removed-cleanup', 'failure cleanup reported' );
    write_deploy_job( $home, 'deploy-nm3', { %{$base_meta}, id => 'deploy-nm3', keep_node_modules => 0 },
        { ok => 1, steps => [ { name => 'remove node_modules', exit => 0 } ] } );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_deploy_status( FakeArgs->new( job_id => 'deploy-nm3' ), $res );
    ok( $ok, 'status accepted' );
    is( $res->{data}{node_modules}, 'removed', 'success-path removal reported' );
    write_deploy_job( $home, 'deploy-nm4', { %{$base_meta}, id => 'deploy-nm4', keep_node_modules => 0 },
        { ok => 0, cleanup => 'cleanup-failed', steps => [ { name => 'npm run build', exit => 1 } ] } );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_deploy_status( FakeArgs->new( job_id => 'deploy-nm4' ), $res );
    ok( $ok, 'status accepted' );
    is( $res->{data}{node_modules}, 'kept', 'failed cleanup still reports kept' );
    write_deploy_job( $home, 'deploy-nm5', { tool => 'deploy', id => 'deploy-nm5', pid => 1, recipe => 'composer_install' },
        { ok => 1, steps => [] } );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_deploy_status( FakeArgs->new( job_id => 'deploy-nm5' ), $res );
    ok( $ok, 'status accepted' );
    ok( !exists $res->{data}{node_modules}, 'composer jobs omit node_modules' );
}

# --- ANSI escapes stripped from captured logs ----------------------------------------------------------------
{
    is( Cpanel::API::UserTools::_strip_ansi("\x1b[39m\x1b[90m.\x1b[0m done\n"),
        ". done\n", 'CSI colour sequences stripped' );
    is( Cpanel::API::UserTools::_strip_ansi("plain text\n"), "plain text\n", 'plain text untouched' );
    is( Cpanel::API::UserTools::_strip_ansi(undef), '', 'undef becomes empty' );

    my $home = make_home();
    my $dir  = "$home/.cpanel/usertools/jobs";
    make_path($dir);
    open my $lfh, '>', "$dir/t.log" or die $!;
    print $lfh "\x1b[1mInstalling\x1b[0m\n\x1b[39m\x1b[90m.\x1b[0m\n";
    close $lfh;
    my $tail = Cpanel::API::UserTools::_deploy_log_tail( { log => "$dir/t.log" }, 1_000_000 );
    is( $tail, "Installing\n.\n", 'job log tail stripped before return' );
    unlike( $tail, qr/\x1b/, 'no escapes left in the tail' );
}

{
    # Composer discovery: missing vs unsafe vs root-owned fixture.
    local $Cpanel::API::UserTools::TEST_COMPOSER = '/nonexistent/composer';
    my ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    ok( !defined $bin, 'missing composer refused' );

    my $home = make_home();
    open my $fh, '>', "$home/composer" or die $!;
    print $fh "#!/bin/sh\nexit 0\n";
    close $fh;
    chmod 0755, "$home/composer";
    local $Cpanel::API::UserTools::TEST_COMPOSER = "$home/composer";
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    ok( !defined $bin, 'non-root-owned composer refused' );

    chmod 0777, "$home/composer";
    $FAKE_UID{"$home/composer"} = 0;
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    ok( !defined $bin, 'group-writable composer refused' );

    chmod 0755, "$home/composer";
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    is( $bin, "$home/composer", 'root-owned 0755 composer accepted' );
    delete $FAKE_UID{"$home/composer"};
}

{
    # Discovery order — admin-set composer_path= in the policy file
    # first, then the default locations; an unsafe configured path stops
    # the search; the not-found message carries no cPanel-path claim.
    my $home = make_home();
    my $conf = "$home/usertools.conf";
    make_path("$home/alt", "$home/d1", "$home/d2");
    my $write_bin = sub {
        my ($p) = @_;
        open my $fh, '>', $p or die $!;
        print $fh "#!/bin/sh\nexit 0\n";
        close $fh;
        chmod 0755, $p;
        $FAKE_UID{$p} = 0;    # root-owned, like a real install
    };
    $write_bin->("$home/alt/composer");
    $write_bin->("$home/d1/composer");
    $write_bin->("$home/d2/composer");

    open my $cf, '>', $conf or die $!;
    print $cf "composer_path=$home/alt/composer\n";
    close $cf;

    local $Cpanel::API::UserTools::TEST_POLICY_FILE = $conf;
    local @Cpanel::API::UserTools::COMPOSER_DEFAULT_PATHS =
      ( "$home/d1/composer", "$home/d2/composer" );

    my ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    is( $bin, "$home/alt/composer", 'composer_path from the conf wins' );

    # No composer_path → the first default location wins.
    open $cf, '>', $conf or die $!;
    print $cf "max_job_seconds=3600\n";
    close $cf;
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    is( $bin, "$home/d1/composer", 'defaults searched after the admin path' );

    # Missing first default → the next one is used.
    unlink "$home/d1/composer";
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    is( $bin, "$home/d2/composer", 'search continues to the next location' );

    # An UNSAFE composer_path stops the search: a perfectly valid default
    # behind it must never be used silently instead.
    open $cf, '>', $conf or die $!;
    print $cf "composer_path=$home/alt/composer\n";
    close $cf;
    chmod 0777, "$home/alt/composer";
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    ok( !defined $bin, 'unsafe composer_path refused' );
    like( $err, qr/unsafe/, 'reason says why' );
    like( $err, qr{\Q$home/alt/composer\E}, 'reason names the configured path' );
    chmod 0755, "$home/alt/composer";

    # A non-absolute composer_path is ignored (never reaches argv).
    open $cf, '>', $conf or die $!;
    print $cf "composer_path=relative/bin/composer\n";
    close $cf;
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    is( $bin, "$home/d2/composer", 'non-absolute composer_path ignored' );

    # Nothing anywhere: the message points at the setting and the install
    # location, and no longer claims cPanel ships a composer.
    unlink "$home/d2/composer";
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    ok( !defined $bin, 'nothing found refused' );
    like( $err, qr/composer_path/,   'message points at the setting' );
    like( $err, qr{usr/local/bin/composer}, 'message points at the install location' );
    unlike( $err, qr/cPanel composer/, 'uncited cPanel composer claim dropped' );
}

{
    # CG2: CageFS visibility — a host-visible composer that CageFS does not
    # mount is reported as not visible (not as found), with the conf.d remedy.
    my $home = make_home();
    my $bin_path = "$home/composer";
    open my $fh, '>', $bin_path or die $!;
    print $fh "#!/bin/sh\nexit 0\n";
    close $fh;
    chmod 0755, $bin_path;
    $FAKE_UID{$bin_path} = 0;
    my $mp = "$home/cagefs.mp";
    open my $mf, '>', $mp or die $!;
    print $mf "# cagefs mount points\n";
    close $mf;
    my $confd = "$home/conf.d";
    make_path($confd);
    local $Cpanel::API::UserTools::TEST_COMPOSER = $bin_path;
    local $Cpanel::API::UserTools::TEST_CAGEFS_MP = $mp;
    local $Cpanel::API::UserTools::TEST_CAGEFS_CONF_D = $confd;
    my ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    ok( !defined $bin, 'CG2: unmounted composer not reported as found' );
    like( $err, qr/not visible to caged users/, 'CG2: reason names cage visibility' );
    like( $err, qr/conf\.d.*INI|INI.*conf\.d|conf\.d INI entry/, 'CG2: reason gives the conf.d remedy' );
    like( $err, qr/cagefsctl --force-update/, 'CG2: reason names force-update' );
    # Listing the path in a conf.d INI entry makes it visible again.
    open my $cf, '>', "$confd/usertools-composer.cfg" or die $!;
    print $cf "[usertools-composer]\ncomment=Composer\npaths=$bin_path\n";
    close $cf;
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    is( $bin, $bin_path, 'CG2: conf.d-listed composer visible again' );
    delete $FAKE_UID{$bin_path};

    # CG2 fail-open: /etc/cagefs/conf.d is commonly 0711, so the user
    # cannot enumerate it — an unprovable absence must never veto a path
    # whose -x check already passed.
    my $home2 = make_home();
    my $bin2 = "$home2/composer";
    open my $fh2, '>', $bin2 or die $!;
    print $fh2 "#!/bin/sh\nexit 0\n";
    close $fh2;
    chmod 0755, $bin2;
    $FAKE_UID{$bin2} = 0;
    my $mp2 = "$home2/cagefs.mp";
    open my $mf2, '>', $mp2 or die $!;
    print $mf2 "# cagefs mount points (no composer)\n";
    close $mf2;
    local $Cpanel::API::UserTools::TEST_COMPOSER = $bin2;
    local $Cpanel::API::UserTools::TEST_CAGEFS_MP = $mp2;
    local $Cpanel::API::UserTools::TEST_CAGEFS_CONF_D = "$home2/conf.d-missing";
    ( $bin, $err ) = Cpanel::API::UserTools::_find_composer();
    is( $bin, $bin2, 'CG2: unreadable conf.d fails open (passing -x stands)' );
    delete $FAKE_UID{$bin2};
}

{
    # CG3: proc_open gate + ext-* requirements.
    my $home = make_app_home();
    my $phpdir = "$home/phpbin/opt/cpanel";
    make_path("$phpdir/ea-php82/root/usr/bin");
    my $php = "$phpdir/ea-php82/root/usr/bin/php";
    open my $fh, '>', $php or die $!;
    print $fh <<'SCRIPT';
#!/bin/bash
args="$*"
if [[ "$args" == *disable_functions* ]]; then
  cat "$(dirname "$0")/disable.txt"
  exit 0
fi
if [[ "$args" == *-m* ]]; then
  cat "$(dirname "$0")/modules.txt"
  exit 0
fi
printf 'simulated artisan output'
exit 0
SCRIPT
    close $fh;
    chmod 0755, $php;
    open my $df, '>', "$phpdir/ea-php82/root/usr/bin/disable.txt" or die $!;
    print $df "proc_open, exec, popen";
    close $df;
    open my $mf, '>', "$phpdir/ea-php82/root/usr/bin/modules.txt" or die $!;
    print $mf "mbstring\njson\n";
    close $mf;
    local $Cpanel::API::UserTools::TEST_PHP_DIR = $phpdir;
    my $dis = Cpanel::API::UserTools::_php_disable_functions( $php, "$home/myapp" );
    like( $dis, qr/proc_open/, 'CG3: disable_functions read from the selected PHP' );
    ok( Cpanel::API::UserTools::_proc_open_disabled( $php, "$home/myapp" ),
        'CG3: proc_open detected as disabled' );
    open $df, '>', "$phpdir/ea-php82/root/usr/bin/disable.txt" or die $!;
    print $df "exec, popen";
    close $df;
    ok( !Cpanel::API::UserTools::_proc_open_disabled( $php, "$home/myapp" ),
        'CG3: clean ini reads as enabled' );
    open $df, '>', "$phpdir/ea-php82/root/usr/bin/disable.txt" or die $!;
    print $df "proc_open, exec";
    close $df;

    # ext-* requirements from composer.json + composer.lock.
    open my $cj, '>', "$home/myapp/composer.json" or die $!;
    print $cj '{"require":{"php":">=8.2","ext-fileinfo":"*","ext-mbstring":"*"}}';
    close $cj;
    open my $cl, '>', "$home/myapp/composer.lock" or die $!;
    print $cl '{"platform":{"ext-fileinfo":"1.0"},"packages":[]}';
    close $cl;
    my $need = Cpanel::API::UserTools::_app_required_extensions("$home/myapp");
    is_deeply( $need, [ 'fileinfo', 'mbstring' ], 'CG3: ext-* collected from json+lock' );
    my $missing = Cpanel::API::UserTools::_php_missing_extensions( $php, "$home/myapp", $need );
    is_deeply( $missing, ['fileinfo'], 'CG3: missing extensions detected (fileinfo)' );

    # Lift policy: only with composer_lift_disable_functions=1 does the
    # recipe add -d disable_functions= (and only for that process).
    my $conf = "$home/usertools.conf";
    open my $pcf, '>', $conf or die $!;
    print $pcf "composer_lift_disable_functions=0\n";
    close $pcf;
    local $Cpanel::API::UserTools::TEST_POLICY_FILE = $conf;
    my $r = Cpanel::API::UserTools::_deploy_recipe_composer(
        $home, "$home/myapp", $php, '/usr/local/bin/composer' );
    ok( !( grep { $_ eq 'disable_functions=' } @{ $r->{steps}[0]{argv} } ),
        'CG3: lift off by default' );
    open $pcf, '>', $conf or die $!;
    print $pcf "composer_lift_disable_functions=1\n";
    close $pcf;
    $r = Cpanel::API::UserTools::_deploy_recipe_composer(
        $home, "$home/myapp", $php, '/usr/local/bin/composer' );
    ok( ( grep { $_ eq 'disable_functions=' } @{ $r->{steps}[0]{argv} } ),
        'CG3: lift adds -d disable_functions= for this process only' );
}

{
    # engines parse: >=N, ^N, N.x, bare, object form, garbage.
    my $home = make_home();
    my $pkg  = "$home/pkg";
    make_path($pkg);
    for my $case (
        [ '{"engines":">=18"}',      '18' ],
        [ '{"engines":"^20"}',       '20' ],
        [ '{"engines":"20.x"}',      '20' ],
        [ '{"engines":"22"}',        '22' ],
        [ '{"engines":{"node":">=16"}}', '16' ],
        [ '{"engines":"latest"}',    undef ],
        [ '{"engines":{"npm":">=9"}}', undef ],
        [ 'not json',                undef ],
      )
    {
        open my $fh, '>', "$pkg/package.json" or die $!;
        print $fh $case->[0];
        close $fh;
        is( Cpanel::API::UserTools::_node_wanted_major($pkg), $case->[1], "engines $case->[0]" );
    }
}

# --- logs ---------------------------------------------------------------------------------------
{
    my $home = make_app_home();
    my $ldir = "$home/myapp/storage/logs";
    make_path($ldir);
    open my $af, '>', "$ldir/app.log" or die $!;
    print $af "line1\nline2\nline3\n";
    close $af;
    open my $bf, '>', "$ldir/evil;rm.log" or die $!;
    print $bf "x\n";
    close $bf;
    symlink "$home/myapp/.env", "$ldir/link.log" or die $!;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_logs( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'logs accepted' );
    my @names = map { $_->{name} } @{ $res->{data}{logs} };
    ok( ( grep { $_ eq 'app.log' } @names ) ? 1 : 0, 'plain log listed' );
    ok( !( grep { $_ eq 'evil;rm.log' } @names ), 'bad name refused' );
    ok( !( grep { $_ eq 'link.log' } @names ), 'symlink refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_log_view(
        FakeArgs->new( app => 'myapp', name => 'app.log' ), $res );
    ok( $ok, 'view accepted' );
    is( $res->{data}{tail}, "line1\nline2\nline3", 'tail content' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_log_view(
        FakeArgs->new( app => 'myapp', name => 'link.log' ), $res );
    ok( !$ok, 'symlink view refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_log_view(
        FakeArgs->new( app => 'myapp', name => '../.env' ), $res );
    ok( !$ok, 'traversal view refused' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_log_clear(
        FakeArgs->new( app => 'myapp', name => 'app.log' ), $res );
    ok( $ok, 'clear accepted' );
    is( -s "$ldir/app.log", 0, 'truncated to zero' );
}

{
    # Tail reads on a large fixture without reading it whole.
    my $home = make_app_home();
    my $ldir = "$home/myapp/storage/logs";
    make_path($ldir);
    open my $bf, '>', "$ldir/big.log" or die $!;
    for my $i ( 1 .. 5000 ) {
        print $bf "padding line $i xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n";
    }
    print $bf "LASTLINE\n";
    close $bf;
    my $size = -s "$ldir/big.log";
    ok( $size > 200000, 'fixture is large' );
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_log_view(
        FakeArgs->new( app => 'myapp', name => 'big.log' ), $res );
    ok( $ok, 'view accepted' );
    like( $res->{data}{tail}, qr/LASTLINE/, 'tail reaches the end' );
    ok( length( $res->{data}{tail} ) <= 70000, 'tail capped' );
    is( $res->{data}{size}, $size, 'full size reported' );
}

# --- maintenance --------------------------------------------------------------------------------
{
    my $sec = Cpanel::API::UserTools::_random_hex_secret();
    like( $sec, qr/^[0-9a-f]{32}$/, 'secret is 32 hex' );

    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    fakephp_conf("$home/myapp");
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_maintenance(
        FakeArgs->new( app => 'myapp', action => 'down' ), $res );
    ok( $ok, 'down accepted' );
    like( $res->{data}{secret}, qr/^[0-9a-f]{32}$/, 'secret returned once' );
    like( $res->{data}{bypass_url}, qr{^https://shop/[0-9a-f]{32}$}, 'bypass URL uses the mapped domain' );
    open my $af, '<', "$home/myapp/.fakephp/argv.log" or die $!;
    my $argv = do { local $/; <$af> };
    close $af;
    like( $argv, qr/down/, 'down reached php' );
    like( $argv, qr/--secret=[0-9a-f]{32}/, 'secret passed as fixed argv' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_maintenance(
        FakeArgs->new( app => 'myapp', action => 'up' ), $res );
    ok( $ok, 'up accepted' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_maintenance(
        FakeArgs->new( app => 'myapp', action => 'reboot' ), $res );
    ok( !$ok, 'bad action refused' );
}

# --- scheduler cron (direct crontab) ---------------------------------------------------------
sub write_fake_crontab {
    my ($dir) = @_;
    my $bin = "$dir/crontab";
    open my $fh, '>', $bin or die $!;
    print $fh "#!/bin/bash\nprintf '%s\\n' \"\$@\" >>\"\$DUMP_CRONTAB_ARGS\"\n"
      . "if [ \"\$1\" = \"-l\" ]; then if [ -f \"\$CRONTAB_FILE\" ]; then cat \"\$CRONTAB_FILE\"; exit 0; "
      . "else echo \"no crontab for testuser\" >&2; exit 1; fi\n"
      . "elif [ \"\$1\" = \"-\" ]; then cat >\"\$CRONTAB_FILE\"; exit 0\nfi\nexit 2\n";
    close $fh;
    chmod 0755, $bin;
    return $bin;
}

{
    # Line build + unsafe path (unchanged).
    my ( $cmd, $err ) = Cpanel::API::UserTools::_cron_command_for(
        '/home/u/myapp', '/opt/cpanel/ea-php82/root/usr/bin/php' );
    is( $cmd, "* * * * * cd '/home/u/myapp' && '/opt/cpanel/ea-php82/root/usr/bin/php' artisan schedule:run >> /dev/null 2>&1",
        'cron line built server-side' );
    ( $cmd, $err ) = Cpanel::API::UserTools::_cron_command_for( '/home/u/my app', '/opt/cpanel/ea-php82/root/usr/bin/php' );
    ok( !defined $cmd, 'unsafe app path refused' );

    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    my $bin = write_fake_crontab($home);
    local $Cpanel::API::UserTools::TEST_CRONTAB = $bin;
    local $ENV{CRONTAB_FILE} = "$home/crontab.txt";
    local $ENV{DUMP_CRONTAB_ARGS} = "$home/crontab-argv.txt";

    # Seed: foreign lines, comments, MAILTO, a $() line (proves no shell),
    # and a foreign schedule:run line without our marker.
    open my $sf, '>', "$home/crontab.txt" or die $!;
    print $sf "MAILTO=ops\@example.test\n"
      . "# owner comment\n"
      . "0 5 * * * /usr/bin/php /home/testuser/other/artisan schedule:run >> /dev/null 2>&1\n"
      . "0 6 * * * echo \$(date) >> /tmp/t.log\n";
    close $sf;
    my $seed = do { open my $fh, '<', "$home/crontab.txt" or die $!; local $/; <$fh> };

    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_cron_add( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'cron add accepted' );
    like( $res->{data}{command}, qr/schedule:run/, 'command returned' );
    my $added_command = $res->{data}{command};

    open my $cf, '<', "$home/crontab.txt" or die $!;
    my $after = do { local $/; <$cf> };
    close $cf;
    like( $after, qr/^\Q$seed\E/m, 'foreign lines preserved byte-for-byte' );
    like( $after, qr/\Q$(date)\E/, 'shell metachars never evaluated' );
    my $marker = '# usertools:schedule ' . Digest::SHA::sha1_hex("$home/myapp");
    like( $after, qr/^\Q$marker\E$/m, 'marker added' );
    is( () = $after =~ /^\Q$marker\E$/gm, 1, 'exactly one marker' );

    open my $af, '<', "$home/crontab-argv.txt" or die $!;
    my @argv = map { chomp; $_ } <$af>;
    close $af;
    ok( ( grep { $_ eq '-l' } @argv ) ? 1 : 0, 'read argv is exactly -l' );
    ok( ( grep { $_ eq '-' } @argv ) ? 1 : 0, 'write argv is exactly -' );
    ok( !grep( { /[|&;]/ } @argv ), 'no shell in argv' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_status( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'cron status accepted' );
    is( $res->{data}{present}, 1, 'line detected' );

    # Idempotent second add.
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_add( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'second add accepted' );
    is( $res->{data}{added}, 0, 'already present' );
    open my $cf2, '<', "$home/crontab.txt" or die $!;
    my $after2 = do { local $/; <$cf2> };
    close $cf2;
    is( () = $after2 =~ /^\Q$marker\E$/gm, 1, 'still exactly one marker' );

    # Removal takes only our marker+line: the foreign schedule:run stays.
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_remove( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'recorded line removed' );
    open my $cf3, '<', "$home/crontab.txt" or die $!;
    my $final = do { local $/; <$cf3> };
    close $cf3;
    is( $final, $seed, 'only our block removed, rest byte-identical' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_remove( FakeArgs->new( app => 'myapp' ), $res );
    ok( !$ok, 'second removal refused' );
    like( $res->{errors}[0][0], qr/Nothing to remove/, 'nothing-to-remove message' );
    delete $ENV{CRONTAB_FILE};
    delete $ENV{DUMP_CRONTAB_ARGS};
}

{
    # Empty crontab (no file at all): add works, marker appended cleanly.
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    my $bin = write_fake_crontab($home);
    local $Cpanel::API::UserTools::TEST_CRONTAB = $bin;
    local $ENV{CRONTAB_FILE} = "$home/crontab.txt";
    local $ENV{DUMP_CRONTAB_ARGS} = "$home/crontab-argv.txt";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_cron_add( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'add on empty crontab accepted' );
    open my $cf, '<', "$home/crontab.txt" or die $!;
    my $content = do { local $/; <$cf> };
    close $cf;
    like( $content, qr/^# usertools:schedule [0-9a-f]{40}$/m, 'marker present' );
    like( $content, qr/schedule:run/, 'line present' );
    delete $ENV{CRONTAB_FILE};
    delete $ENV{DUMP_CRONTAB_ARGS};
}

{
    # Hand-edited line under our marker is left alone by add and remove.
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    my $bin = write_fake_crontab($home);
    local $Cpanel::API::UserTools::TEST_CRONTAB = $bin;
    local $ENV{CRONTAB_FILE} = "$home/crontab.txt";
    local $ENV{DUMP_CRONTAB_ARGS} = "$home/crontab-argv.txt";
    my $marker = '# usertools:schedule ' . Digest::SHA::sha1_hex("$home/myapp");
    open my $hf, '>', "$home/crontab.txt" or die $!;
    print $hf "$marker\n0 5 * * * /bin/true\n";
    close $hf;
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_cron_add( FakeArgs->new( app => 'myapp' ), $res );
    ok( !$ok, 'add refuses a hand-edited block' );
    like( $res->{errors}[0][1], qr/hand/, 'reason names the edit' );
    make_path("$home/.cpanel/usertools");
    open my $jf, '>', "$home/.cpanel/usertools/cron.json" or die $!;
    print $jf '{"lines":{"myapp":{"marker":"x","command":"y","added":1}}}';
    close $jf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_remove( FakeArgs->new( app => 'myapp' ), $res );
    ok( !$ok, 'remove refuses a hand-edited block' );
    open my $cf, '<', "$home/crontab.txt" or die $!;
    my $content = do { local $/; <$cf> };
    close $cf;
    is( $content, "$marker\n0 5 * * * /bin/true\n", 'hand edit untouched' );
    delete $ENV{CRONTAB_FILE};
    delete $ENV{DUMP_CRONTAB_ARGS};
}

{
    # CG4: CloudLinux wrapper inserts SHELL="..." between marker and line.
    # Remove skips blank/env lines, matches the command, and keeps the env.
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    my $bin = write_fake_crontab($home);
    local $Cpanel::API::UserTools::TEST_CRONTAB = $bin;
    local $ENV{CRONTAB_FILE} = "$home/crontab.txt";
    local $ENV{DUMP_CRONTAB_ARGS} = "$home/crontab-argv.txt";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_cron_add( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'CG4: add accepted' );
    my $marker = '# usertools:schedule ' . Digest::SHA::sha1_hex("$home/myapp");
    open my $cf, '<', "$home/crontab.txt" or die $!;
    my $after = do { local $/; <$cf> };
    close $cf;
    # Simulate the wrapper rewrite: SHELL between marker and command.
    my $cmd = $after;
    $cmd =~ s/^\Q$marker\E\n//m;
    chomp $cmd;
    open my $wf, '>', "$home/crontab.txt" or die $!;
    print $wf "$marker\nSHELL=\"/usr/local/cpanel/bin/jailshell\"\n$cmd\n";
    close $wf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_status( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'CG4: status accepted with wrapper env' );
    is( $res->{data}{present}, 1, 'CG4: line still detected past SHELL' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_remove( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'CG4: remove works past the wrapper SHELL' );
    open my $rf, '<', "$home/crontab.txt" or die $!;
    my $final = do { local $/; <$rf> };
    close $rf;
    like( $final, qr/^SHELL=/m, 'CG4: wrapper env lines kept' );
    unlike( $final, qr/schedule:run/, 'CG4: command gone' );
    unlike( $final, qr/usertools:schedule/, 'CG4: marker gone' );
    delete $ENV{CRONTAB_FILE};
    delete $ENV{DUMP_CRONTAB_ARGS};
}

{
    # CG4: backup banner on stderr ignored; garbage on stdout refused.
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    my $bin = "$home/crontab";
    open my $fh, '>', $bin or die $!;
    print $fh "#!/bin/bash\n"
      . "if [ \"\$1\" = \"-l\" ]; then echo \"Backup of testuser's previous crontab saved to /tmp/bak\" >&2; "
      . "if [ -f \"\$CRONTAB_FILE\" ]; then cat \"\$CRONTAB_FILE\"; exit 0; "
      . "else echo \"no crontab for testuser\" >&2; exit 1; fi\n"
      . "elif [ \"\$1\" = \"-\" ]; then cat >\"\$CRONTAB_FILE\"; exit 0\nfi\nexit 2\n";
    close $fh;
    chmod 0755, $bin;
    local $Cpanel::API::UserTools::TEST_CRONTAB = $bin;
    local $ENV{CRONTAB_FILE} = "$home/crontab.txt";
    local $ENV{DUMP_CRONTAB_ARGS} = "$home/crontab-argv.txt";
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_cron_add( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'CG4: banner on stderr ignored' );
    # Garbage on stdout: the next write must refuse, never clobber.
    open my $gf, '>', "$home/crontab.txt" or die $!;
    print $gf "hello world\n";
    close $gf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_cron_add( FakeArgs->new( app => 'myapp' ), $res );
    ok( !$ok, 'CG4: garbage on stdout refused' );
    like( $res->{errors}[0][1], qr/unrecognized/, 'CG4: refusal names the content' );
    open my $cf, '<', "$home/crontab.txt" or die $!;
    my $kept = do { local $/; <$cf> };
    close $cf;
    is( $kept, "hello world\n", 'CG4: garbage left untouched' );
    delete $ENV{CRONTAB_FILE};
    delete $ENV{DUMP_CRONTAB_ARGS};
}

# --- .env parser + readiness + production switch ------------------------------------------
{
    # Round-trip on every quote style, export, comments and CRLF: only the
    # two keys change, everything else byte-for-byte.
    my $orig = "# comment\n"
      . "APP_NAME=Acme\n"
      . "APP_ENV=local\n"
      . "APP_DEBUG=true\n"
      . "APP_KEY=\"base64:abc==\"\n"
      . "DB_PASSWORD='s3cret'\n"
      . "export MAIL_PASSWORD=mailpw\n"
      . "\n"
      . "EMPTY=\n"
      . "CRLF_LINE=1\r\n";
    my $lines = Cpanel::API::UserTools::_parse_dotenv_lines($orig);
    my $new = Cpanel::API::UserTools::_dotenv_set_keys(
        $lines, { APP_ENV => 'production', APP_DEBUG => 'false' } );
    like( $new, qr/^APP_ENV=production$/m, 'env switched' );
    like( $new, qr/^APP_DEBUG=false$/m, 'debug switched' );
    like( $new, qr/^APP_KEY="base64:abc=="$/m, 'quoted value kept' );
    like( $new, qr/^DB_PASSWORD='s3cret'$/m, 'single quotes kept' );
    like( $new, qr/^export MAIL_PASSWORD=mailpw$/m, 'export kept' );
    like( $new, qr/^# comment$/m, 'comments kept' );
    like( $new, qr/CRLF_LINE=1\r\n/, 'CRLF kept' );
    unlike( $new, qr/APP_ENV=local/, 'no stale value' );

    # Append-when-missing.
    $new = Cpanel::API::UserTools::_dotenv_set_keys(
        Cpanel::API::UserTools::_parse_dotenv_lines("APP_NAME=x\n"), { APP_ENV => 'production' } );
    like( $new, qr/^APP_ENV=production$/m, 'missing key appended' );
}

{
    my $home = make_app_home();
    # Fixture: secrets on lines ADJACENT to APP_ENV/APP_DEBUG (both
    # before and after), so any line-based context in a response would echo
    # them. Values must never appear in any of these calls' JSON.
    open my $ef, '>', "$home/myapp/.env" or die $!;
    print $ef "APP_KEY=base64:supersecretkey==\n"
      . "DB_PASSWORD=dbpw\n"
      . "APP_ENV=local\n"
      . "MAIL_PASSWORD=mailpw\n"
      . "APP_DEBUG=true\n"
      . "APP_NAME=Acme\n";
    close $ef;
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    my $udir = "$home/userdata";
    make_path("$udir/testuser");
    local $Cpanel::API::UserTools::TEST_DOMAIN_DATA_DIR = $udir;
    open my $df, '>', "$udir/testuser/shop" or die $!;
    print $df "---\ndocumentroot: $home/myapp/public\n";
    close $df;
    no warnings 'redefine';
    local *Cpanel::API::UserTools::_http_get_capped = sub {
        return ( { success => 0, status => 404 }, 0, '' );
    };
    fakephp_conf("$home/myapp");

    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_readiness( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'readiness accepted' );
    is( $res->{data}{debug_true}, 1, 'debug flagged' );
    is( $res->{data}{env_production}, 0, 'non-production flagged' );
    is( $res->{data}{key_empty}, 0, 'set key not flagged as empty' );
    is( $res->{data}{live}, 1, 'live domain seen' );
    my $json = JSON::PP->new()->encode( $res->{data} );
    unlike( $json, qr/dbpw/,   'readiness: no DB_PASSWORD value' );
    unlike( $json, qr/mailpw/, 'readiness: no MAIL_PASSWORD value' );
    unlike( $json, qr/supersecretkey/, 'readiness: no APP_KEY value' );

    # env_check: the prober returns URLs/status/verdicts only (no bodies).
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_env_check( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'env check accepted' );
    $json = JSON::PP->new()->encode( $res->{data} );
    unlike( $json, qr/dbpw/,           'env_check: no DB_PASSWORD value' );
    unlike( $json, qr/mailpw/,         'env_check: no MAIL_PASSWORD value' );
    unlike( $json, qr/supersecretkey/, 'env_check: no APP_KEY value' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_production_preview( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'preview accepted' );
    is( $res->{data}{unchanged}, 0, 'preview reports changes' );
    is_deeply(
        $res->{data}{changes},
        [
            { key => 'APP_ENV',   from => 'local', to => 'production' },
            { key => 'APP_DEBUG', from => 'true',  to => 'false' },
        ],
        'structured changes list built from the two keys only'
    );
    ok( !exists $res->{data}{diff}, 'no diff text in the preview response' );
    $json = JSON::PP->new()->encode( $res->{data} );
    unlike( $json, qr/dbpw/,           'preview: no DB_PASSWORD value' );
    unlike( $json, qr/mailpw/,         'preview: no MAIL_PASSWORD value' );
    unlike( $json, qr/supersecretkey/, 'preview: no APP_KEY value' );
    unlike( $json, qr/base64/,         'preview: no key material at all' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_production_apply( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'apply accepted' );
    is( $res->{data}{env_production}, 1, 'production after apply' );
    is( $res->{data}{debug_true}, 0, 'debug off after apply' );
    open my $cf, '<', "$home/myapp/.env" or die $!;
    my $env = do { local $/; <$cf> };
    close $cf;
    like( $env, qr/^APP_ENV=production$/m, 'file switched' );
    like( $env, qr/^DB_PASSWORD=dbpw$/m, 'other values untouched' );
    is( ( stat("$home/myapp/.env") )[2] & 07777, 0600, '.env stays 0600' );
    ok( -f "$home/myapp/.env.usertools-orig", 'never-pruned original kept' );
    $json = JSON::PP->new()->encode( $res->{data} );
    unlike( $json, qr/dbpw/,           'apply: no DB_PASSWORD value' );
    unlike( $json, qr/mailpw/,         'apply: no MAIL_PASSWORD value' );
    unlike( $json, qr/supersecretkey/, 'apply: no APP_KEY value' );

    # Preview of the already-production file: unchanged, still no values.
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_production_preview( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'preview after apply accepted' );
    is( $res->{data}{unchanged}, 1, 'unchanged reported' );
    is_deeply( $res->{data}{changes}, [], 'empty changes list when nothing to do' );
    $json = JSON::PP->new()->encode( $res->{data} );
    unlike( $json, qr/dbpw/,           'unchanged preview: no DB_PASSWORD value' );
    unlike( $json, qr/mailpw/,         'unchanged preview: no MAIL_PASSWORD value' );
    unlike( $json, qr/supersecretkey/, 'unchanged preview: no APP_KEY value' );

    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_production_undo( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'undo accepted' );
    open my $uf, '<', "$home/myapp/.env" or die $!;
    my $restored = do { local $/; <$uf> };
    close $uf;
    like( $restored, qr/^APP_ENV=local$/m, 'byte-exact undo' );
    like( $restored, qr/^APP_DEBUG=true$/m, 'debug restored' );
    $json = JSON::PP->new()->encode( $res->{data} );
    unlike( $json, qr/dbpw/,           'undo: no DB_PASSWORD value' );
    unlike( $json, qr/mailpw/,         'undo: no MAIL_PASSWORD value' );
    unlike( $json, qr/supersecretkey/, 'undo: no APP_KEY value' );

    # key_generate with the key set: refused, and the refusal carries the
    # key NAME only, never its value.
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_key_generate( FakeArgs->new( app => 'myapp' ), $res );
    ok( !$ok, 'key generate refused when set' );
    $json = JSON::PP->new()->encode( $res->{errors} );
    unlike( $json, qr/supersecretkey/, 'refusal names the key, not its value' );

    # key_generate with the key empty: accepted; response stays value-free.
    open my $kf, '>', "$home/myapp/.env" or die $!;
    print $kf "APP_ENV=local\nDB_PASSWORD=dbpw\nAPP_KEY=\nMAIL_PASSWORD=mailpw\n";
    close $kf;
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_key_generate( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'key generate accepted when empty' );
    is( $res->{data}{key_set}, 0, 'flag reflects the re-read (fake PHP writes nothing)' );
    $json = JSON::PP->new()->encode( $res->{data} );
    unlike( $json, qr/dbpw/,   'key_generate: no DB_PASSWORD value' );
    unlike( $json, qr/mailpw/, 'key_generate: no MAIL_PASSWORD value' );
}

# --- live recipe jobs --------------------------------------------------------------------
{
    # Composer start -> done, through the real worker (fast fixtures).
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    open my $cf, '>', "$home/composer" or die $!;
    print $cf "#!/bin/sh\nexit 0\n";
    close $cf;
    chmod 0755, "$home/composer";
    $FAKE_UID{"$home/composer"} = 0;
    local $Cpanel::API::UserTools::TEST_COMPOSER = "$home/composer";
    local $Cpanel::API::UserTools::TEST_ENGINE_BIN = 'python3';
    local $Cpanel::API::UserTools::TEST_RECIPE_WORKER = "$FindBin::Bin/../engine/recipe_worker.py";
    local $ENV{USERTOOLS_TESTING} = '1';
    fakephp_conf("$home/myapp");
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_composer_start( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'composer start accepted' );
    my $job_id = $res->{data}{job_id};
    ok( defined $job_id, 'job id returned' );
    my $state = '';
    for ( 1 .. 50 ) {
        select( undef, undef, undef, 0.2 );
        my $st = FakeResult->new();
        Cpanel::API::UserTools::app_helper_deploy_status( FakeArgs->new( job_id => $job_id ), $st );
        $state = $st->{data}{state};
        last if $state eq 'done' || $state eq 'failed';
    }
    is( $state, 'done', 'composer job completes' );
    open my $af, '<', "$home/.fakephp/argv.log" or die $!;
    my $argv = do { local $/; <$af> };
    close $af;
    like( $argv, qr/install/, 'composer install ran under php' );
    like( $argv, qr/^ARGV:-d$/m, '-d reached the spawned php' );
    like( $argv, qr/^ARGV:allow_url_fopen=1$/m, 'allow_url_fopen=1 reached the spawned php' );
    like( $argv, qr/^ARGV:\Q$home\/composer\E$/m, 'composer script follows the -d pair' );
    delete $FAKE_UID{"$home/composer"};
    delete $ENV{USERTOOLS_TESTING};
}

{
    # Cancel stops a slow job.
    my $home = make_app_home();
    make_fake_php("$home/phpbin");
    local $Cpanel::API::UserTools::TEST_PHP_DIR = "$home/phpbin/opt/cpanel";
    $Cpanel::API::UserTools::TEST_ARTISAN_TIMEOUT = 30;
    open my $cf, '>', "$home/composer" or die $!;
    print $cf "#!/bin/sh\nexit 0\n";
    close $cf;
    chmod 0755, "$home/composer";
    $FAKE_UID{"$home/composer"} = 0;
    local $Cpanel::API::UserTools::TEST_COMPOSER = "$home/composer";
    local $Cpanel::API::UserTools::TEST_ENGINE_BIN = 'python3';
    local $Cpanel::API::UserTools::TEST_RECIPE_WORKER = "$FindBin::Bin/../engine/recipe_worker.py";
    local $ENV{USERTOOLS_TESTING} = '1';
    fakephp_conf( $home, sleep => '30' );
    my $res = FakeResult->new();
    my $ok = Cpanel::API::UserTools::app_helper_composer_start( FakeArgs->new( app => 'myapp' ), $res );
    ok( $ok, 'composer start accepted' );
    my $job_id = $res->{data}{job_id};
    select( undef, undef, undef, 0.5 );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_deploy_cancel( FakeArgs->new( job_id => $job_id ), $res );
    ok( $ok, 'cancel accepted' );
    is( $res->{data}{cancelled}, 1, 'cancel reported' );
    $res = FakeResult->new();
    $ok = Cpanel::API::UserTools::app_helper_deploy_status( FakeArgs->new( job_id => $job_id ), $res );
    ok( $ok, 'status accepted' );
    is( $res->{data}{state}, 'cancelled', 'cancelled state' );
    delete $FAKE_UID{"$home/composer"};
    delete $ENV{USERTOOLS_TESTING};
}

done_testing();

