# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package Cpanel::API::UserTools;

use strict;
use warnings;

our $VERSION = '0.1.2';

# Cpanel Dependencies
use Cpanel                   ();
use Cpanel::API              ();
use Cpanel::Locale           ();
use Cpanel::Logger           ();
use Cpanel::AdminBin::Call   ();

use File::Path qw(make_path);
use IO::Compress::Gzip qw(gzip $GzipError);
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use JSON::PP ();    # core; flat-record decode only
use Digest::SHA ();   # core; cron marker ids only
use Cwd qw(realpath);
use Time::HiRes qw(usleep);
use POSIX qw(setsid WNOHANG);
use Fcntl qw(:flock);

# Feature name for Fix Home Permissions (tool B). It must match the
# "feature" value of this tool's entry in plugin/install.json, so WHM's
# Feature Manager and the API layer gate the same name.
our $FEATURE_FIX_HOME = 'usertools_fix_home';
our $FEATURE_BULK_PERMS = 'usertools_bulk_perms';
our $FEATURE_OWNERSHIP_REPORT = 'usertools_ownership_report';
our $FEATURE_SHELL = 'usertools_shell';
our $FEATURE_APP_HELPER = 'usertools_app_helper';
our $FEATURE_SPACE_CLEANER = 'usertools_space_cleaner';
our $FEATURE_SITE_DOCTOR = 'usertools_site_doctor';
our $FEATURE_EXPOSED_FILES = 'usertools_exposed_files';
our $FEATURE_CRON_DOCTOR = 'usertools_cron_doctor';
our $FEATURE_ACTIVITY = 'usertools_activity';

our %API = (
    'home_permissions_check' => { 'needs_feature' => $FEATURE_FIX_HOME },
    'home_permissions_fix'   => { 'needs_feature' => $FEATURE_FIX_HOME },
    'home_permissions_undo'  => { 'needs_feature' => $FEATURE_FIX_HOME },
    'bulk_permissions_start'  => { 'needs_feature' => $FEATURE_BULK_PERMS },
    'bulk_permissions_status' => { 'needs_feature' => $FEATURE_BULK_PERMS },
    'bulk_permissions_cancel' => { 'needs_feature' => $FEATURE_BULK_PERMS },
    'bulk_permissions_undo'   => { 'needs_feature' => $FEATURE_BULK_PERMS },
    'ownership_report_start'  => { 'needs_feature' => $FEATURE_OWNERSHIP_REPORT },
    'ownership_report_status' => { 'needs_feature' => $FEATURE_OWNERSHIP_REPORT },
    'ownership_report_cancel' => { 'needs_feature' => $FEATURE_OWNERSHIP_REPORT },
    'space_scan_start'   => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_scan_status'  => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_scan_cancel'  => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_clean_start'  => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_clean_status' => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_clean_cancel' => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_trash_list'    => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_trash_restore' => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'space_trash_empty'   => { 'needs_feature' => $FEATURE_SPACE_CLEANER },
    'doctor_scan_start'   => { 'needs_feature' => $FEATURE_SITE_DOCTOR },
    'doctor_scan_status'  => { 'needs_feature' => $FEATURE_SITE_DOCTOR },
    'doctor_scan_cancel'  => { 'needs_feature' => $FEATURE_SITE_DOCTOR },
    'doctor_htaccess_preview' => { 'needs_feature' => $FEATURE_SITE_DOCTOR },
    'doctor_htaccess_fix'     => { 'needs_feature' => $FEATURE_SITE_DOCTOR },
    'doctor_htaccess_undo'    => { 'needs_feature' => $FEATURE_SITE_DOCTOR },
    'exposed_scan_start'  => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'exposed_scan_status' => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'exposed_scan_cancel' => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'exposed_move'          => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'exposed_restore'       => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'exposed_quarantine_list' => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'exposed_block'   => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'exposed_unblock' => { 'needs_feature' => $FEATURE_EXPOSED_FILES },
    'cron_scan'      => { 'needs_feature' => $FEATURE_CRON_DOCTOR },
    'cron_fix_preview' => { 'needs_feature' => $FEATURE_CRON_DOCTOR },
    'cron_fix_output'  => { 'needs_feature' => $FEATURE_CRON_DOCTOR },
    'cron_undo'        => { 'needs_feature' => $FEATURE_CRON_DOCTOR },
    'activity_list'  => { 'needs_feature' => $FEATURE_ACTIVITY },
    'shell_status' => { 'needs_feature' => $FEATURE_SHELL },
    'shell_set'    => { 'needs_feature' => $FEATURE_SHELL },
    'app_helper_list'      => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_add'       => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_remove'    => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_artisan'   => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_fix_perms' => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_env_check' => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_docroot_preview' => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_set_docroot'     => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_undo_docroot'    => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_htaccess_preview' => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_htaccess_apply'   => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_htaccess_undo'    => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_primary_check' => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_primary_set'   => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_deploy_info'     => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_composer_start'  => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_npm_start'       => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_deploy_status'   => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_deploy_cancel'   => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_logs'            => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_log_view'        => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_log_clear'       => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_maintenance'     => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_cron_status'     => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_cron_add'        => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_cron_remove'     => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_readiness'       => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_production_preview' => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_production_apply'   => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_production_undo'    => { 'needs_feature' => $FEATURE_APP_HELPER },
    'app_helper_key_generate'    => { 'needs_feature' => $FEATURE_APP_HELPER },
);

# Install path of the engine on a cPanel server (install.sh).
our $ENGINE_PATH = '/usr/local/cpanel/3rdparty/usertools/bin/perm_engine.py';
our $SPACE_ENGINE_PATH =
  '/usr/local/cpanel/3rdparty/usertools/bin/space_cleaner.py';
our $SITE_ENGINE_PATH =
  '/usr/local/cpanel/3rdparty/usertools/bin/site_doctor.py';
our $ENGINE_PYTHON = '/usr/bin/python3';

# Fixed Space Cleaner categories: the only selectable things. The engine
# enforces the same list; anything outside it is never touched.
our @SPACE_CATEGORIES = qw(
  error_logs core_dumps app_cache wp_cache dev_caches usertools_old
);

# Test seams (see tests/test_usertools_pm.t): undef in production.
# $TEST_ENGINE_BIN/$TEST_ENGINE redirect engine spawns at the repo's engine;
# with USERTOOLS_TESTING=1 the spawn also passes --home at the fixture so
# tests never touch the tester's real home. $TEST_ARTISAN_TIMEOUT overrides
# the 120 s artisan timeout;
# $TEST_PHP_DIR fakes /opt/cpanel for PHP selection; $TEST_DOMAIN_DATA_DIR
# fakes /var/cpanel/userdata for domain enumeration; $TEST_CPANEL_CONFIG
# fakes /var/cpanel/cpanel.config for the docroot-restriction tweak;
# $TEST_POLICY_FILE fakes /etc/usertools.conf for user-side policy reads;
# $TEST_ALT_PHP_DIR fakes /opt/alt for CloudLinux alt-php; Node.js resolvers
# take explicit base dirs (tests pass fixture trees); $TEST_RECIPE_WORKER
# fakes the deploy worker script; $TEST_COMPOSER fakes the composer binary;
# $TEST_CRONTAB fakes the crontab binary. In-process UAPI calls
# (Cpanel::API::execute) are programmed directly in tests; there is no CLI
# seam because user-context code never shells to `uapi --user=`.
# $TEST_SPACE_ENGINE fakes the Space Cleaner engine script the same way
# $TEST_ENGINE fakes the permission engine. $TEST_SITE_ENGINE fakes the
# site engine; $TEST_EXPOSED_PROBE, when defined, replaces the live
# post-action HTTP re-probe with a canned {status, exposed} answer;
# $TEST_SITE_IP_OVERRIDE and $TEST_SITE_PORT_OVERRIDE point probes at a
# local test server.
our ( $TEST_USER, $TEST_HOME, $TEST_ENGINE_BIN, $TEST_ENGINE,
    $TEST_ARTISAN_TIMEOUT, $TEST_PHP_DIR, $TEST_DOMAIN_DATA_DIR,
    $TEST_ENV_BUDGET_SECONDS, $TEST_CPANEL_CONFIG, $TEST_POLICY_FILE,
    $TEST_ALT_PHP_DIR, $TEST_RECIPE_WORKER, $TEST_COMPOSER, $TEST_CRONTAB,
    $TEST_CAGEFS_MP, $TEST_CAGEFS_CONF_D, $TEST_SPACE_ENGINE, $TEST_SITE_ENGINE,
    $TEST_EXPOSED_PROBE, $TEST_SITE_IP_OVERRIDE, $TEST_SITE_PORT_OVERRIDE );

# Composer locations after the admin-set composer_path: a plain
# package var so tests can localise it instead of depending on whatever
# happens to be installed on the test machine.
our @COMPOSER_DEFAULT_PATHS = (
    '/usr/local/bin/composer',        # getcomposer.org global install
    '/opt/cpanel/composer/bin/composer',
);

# ---------------------------------------------------------------------------
# Localisation: every user-visible string goes through maketext when the
# locale system is available, otherwise plain English (sprintf fallback).
# $result->error() arguments stay exact literals (cPanel localises those
# server-side from its own catalogs), so they are NOT wrapped here.
# ---------------------------------------------------------------------------

sub __ {
    my ( $msg, @args ) = @_;
    my $handle = eval { Cpanel::Locale->get_handle() };
    if ( $handle && eval { $handle->can('maketext') } ) {
        my $text = eval { $handle->maketext( $msg, @args ) };
        return $text if defined $text;
    }
    my $fmt = $msg;
    $fmt =~ s/\[_(\d+)\]/%s/g;
    return @args ? sprintf( $fmt, @args ) : $fmt;
}

# ---------------------------------------------------------------------------
# Caller identity and FileProtect detection
# ---------------------------------------------------------------------------

sub _caller_info {
    # Returns ( username, uid, home ). Runs as the cPanel user; never root.
    my $uid = $>;
    my $user = defined $TEST_USER ? $TEST_USER : ( getpwuid($uid) )[0];
    my $home = defined $TEST_HOME ? $TEST_HOME : ( getpwuid($uid) )[7];
    return ( $user, $uid, $home );
}

sub _fileprotect_on {
    my ( $home, $touch ) = @_;
    # FileProtect is a touch file: /var/cpanel/fileprotect exists => ON.
    # A stat is enough and works for users when /var/cpanel is searchable.
    $touch = '/var/cpanel/fileprotect' unless defined $touch;
    if ( lstat $touch ) {
        return 1;
    }
    if ( $!{EACCES} ) {
        # Unknown (cannot even stat it): fall back to the public_html group.
        my @st = lstat "$home/public_html";
        if (@st) {
            my $grp = ( getgrgid( $st[5] ) )[0];
            return ( defined $grp && $grp eq 'nobody' ) ? 1 : 0;
        }
        return 1;    # nothing readable at all: secure default
    }
    # Definitively absent (ENOENT and friends): OFF.
    return 0;
}

# ---------------------------------------------------------------------------
# Required-state table (FileProtect-on variant shown; public_html adapts)
# ---------------------------------------------------------------------------

sub _required_rows {
    my ( $user, $fileprotect_on ) = @_;
    my $ph_mode  = $fileprotect_on ? 0750 : 0755;
    my $ph_group = $fileprotect_on ? 'nobody' : $user;
    return (
        { key => 'home',            label => 'Home directory',           rel => '',                      mode => 0711, owner => $user, group => $user,   dir => 1, creatable => 0 },
        { key => 'etc',             label => 'Mail configuration (etc)', rel => 'etc',                   mode => 0750, owner => $user, group => 'mail',  dir => 1, creatable => 0 },
        { key => 'mail',            label => 'Mail storage (mail)',      rel => 'mail',                  mode => 0751, owner => $user, group => $user,   dir => 1, creatable => 0 },
        { key => 'public_ftp',      label => 'Anonymous FTP (public_ftp)', rel => 'public_ftp',           mode => 0750, owner => $user, group => $user,   dir => 1, creatable => 0 },
        { key => 'public_html',     label => 'Website files (public_html)', rel => 'public_html',        mode => $ph_mode, owner => $user, group => $ph_group, dir => 1, creatable => 0 },
        { key => 'tmp',             label => 'Temporary files (tmp)',    rel => 'tmp',                   mode => 0755, owner => $user, group => $user,   dir => 1, creatable => 1 },
        { key => 'ssl',             label => 'SSL storage (ssl)',        rel => 'ssl',                   mode => 0755, owner => $user, group => $user,   dir => 1, creatable => 0 },
        { key => 'ssl_db',          label => 'SSL database (ssl.db)',    rel => 'ssl/ssl.db',            mode => 0600, owner => $user, group => $user,   dir => 0, creatable => 0 },
        { key => 'ssl_db_cache',    label => 'SSL database cache',       rel => 'ssl/ssl.db.cache',      mode => 0600, owner => $user, group => $user,   dir => 0, creatable => 0 },
        { key => 'ssh',             label => 'SSH directory (.ssh)',     rel => '.ssh',                  mode => 0700, owner => $user, group => $user,   dir => 1, creatable => 1 },
        { key => 'authorized_keys', label => 'SSH authorized keys',      rel => '.ssh/authorized_keys',  mode => 0600, owner => $user, group => $user,   dir => 0, creatable => 0 },
    );
}

# ---------------------------------------------------------------------------
# Check (read-only) and fix (modes only)
# ---------------------------------------------------------------------------

sub _group_is {
    my ( $gid, $expected_name ) = @_;
    my @exp = getgrnam($expected_name);
    if (@exp) {
        return $gid == $exp[2] ? 1 : 0;
    }
    my $got = ( getgrgid($gid) )[0];    # name fallback if group is unknown
    return ( defined $got && $got eq $expected_name ) ? 1 : 0;
}

sub _check_path {
    my ( $home, $uid, $row ) = @_;
    my $path = $row->{rel} eq '' ? $home : "$home/$row->{rel}";
    my %out = (
        key            => $row->{key},
        label          => $row->{label},
        path           => $path,
        required_mode  => sprintf( '%04o', $row->{mode} ),
        required_owner => $row->{owner},
        required_group => $row->{group},
        creatable      => $row->{creatable} ? 1 : 0,
    );
    my @st = lstat $path;    # never follows symlinks
    if ( !@st ) {
        $out{exists} = 0;
        $out{status} = 'missing';
        return \%out;
    }
    $out{exists} = 1;
    if ( -l _ ) {
        $out{symlink} = 1;
        $out{status}  = 'symlink';
        return \%out;
    }
    my $mode = $st[2] & 07777;
    my $owner_name = ( getpwuid( $st[4] ) )[0];
    my $group_name = ( getgrgid( $st[5] ) )[0];
    $out{current_mode}  = sprintf( '%04o', $mode );
    $out{current_owner} = defined $owner_name ? $owner_name : "$st[4]";
    $out{current_group} = defined $group_name ? $group_name : "$st[5]";
    $out{mode_ok}  = ( $mode == $row->{mode} ) ? 1 : 0;
    $out{owner_ok} = ( $st[4] == $uid )        ? 1 : 0;
    $out{group_ok} = _group_is( $st[5], $row->{group} ) ? 1 : 0;
    if ( $out{mode_ok} && $out{owner_ok} && $out{group_ok} ) {
        $out{status} = 'ok';
    }
    elsif ( !$out{owner_ok} || !$out{group_ok} ) {
        $out{status} = 'owner_mismatch';    # needs the hosting provider
    }
    else {
        $out{status} = 'mode_mismatch';     # Fix Modes can repair this
    }
    return \%out;
}

sub _fix_path {
    my ( $home, $uid, $row ) = @_;
    my $path = $row->{rel} eq '' ? $home : "$home/$row->{rel}";
    my $rel = $row->{rel} eq '' ? '.' : $row->{rel};
    my %out = ( key => $row->{key}, label => $row->{label}, path => $path, rel => $rel );
    my @st = lstat $path;    # never follows symlinks
    if ( !@st ) {
        if ( $row->{creatable} ) {
            if ( !mkdir $path, $row->{mode} ) {
                $out{action} = 'error';
                $out{detail} = __( 'cannot create directory: [_1]', "$!" );
                return \%out;
            }
            chmod $row->{mode}, $path;    # umask-proof exact mode
            $out{action} = 'created';
            $out{to}     = sprintf( '%04o', $row->{mode} );
            return \%out;
        }
        $out{action} = 'missing';
        $out{detail} = __( 'missing; only tmp and .ssh are created automatically' );
        return \%out;
    }
    if ( -l _ ) {
        $out{action} = 'skipped_symlink';
        $out{detail} = __( 'is a symlink; left alone' );
        return \%out;
    }
    if ( !-f _ && !-d _ ) {
        $out{action} = 'skipped_special';
        $out{detail} = __( 'not a regular file or directory; left alone' );
        return \%out;
    }
    if ( $st[4] != $uid ) {
        $out{action} = 'not_owned';
        $out{detail} = __( 'not owned by you; needs your hosting provider' );
        return \%out;
    }
    my $mode = $st[2] & 07777;
    if ( $mode == $row->{mode} ) {
        $out{action} = 'ok';
        return \%out;
    }
    if ( chmod $row->{mode}, $path ) {
        $out{action} = 'fixed';
        $out{from}   = sprintf( '%04o', $mode );
        $out{to}     = sprintf( '%04o', $row->{mode} );
    }
    else {
        $out{action} = 'error';
        $out{detail} = __( 'chmod failed: [_1]', "$!" );
    }
    return \%out;
}

# ---------------------------------------------------------------------------
# Undo journals (same file format as engine/perm_engine.py: gzip JSON lines,
# header {v,tool,home,scope,started} then {path,from,to} with home-relative
# paths and %04o modes). Only `fixed` entries are
# journaled (created dirs have no previous mode); only the newest 3 journals
# are kept. Restores never bring back setuid/setgid/sticky bits.
# ---------------------------------------------------------------------------

sub _undo_dir {
    my ($home) = @_;
    return "$home/.cpanel/usertools/undo";
}

sub _journal_timestamp {
    my @t = gmtime();
    return sprintf( "%04d%02d%02dT%02d%02d%02d-%d",
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0], $$ );
}

sub _valid_journal_rel {
    my ($rel) = @_;
    return 0 unless defined $rel && $rel ne '';
    return 1 if $rel eq '.';
    return 0 if $rel =~ m{^/} || $rel =~ m{(^|/)\.\.(/|$)};
    return 1;
}

sub _latest_journal {
    my ( $undo_dir, $prefix ) = @_;
    return undef unless opendir( my $dh, $undo_dir );
    my @names = sort grep { /^\Q$prefix\E.*\.jsonl\.gz$/ } readdir $dh;
    closedir $dh;
    return @names ? "$undo_dir/$names[-1]" : undef;
}

sub _read_journal {
    my ($path) = @_;
    my $content;
    return undef unless gunzip( $path => \$content );
    my @lines = grep { $_ ne '' } split /\n/, $content;
    return undef unless @lines;
    my $json = JSON::PP->new();
    my @out;
    for my $line (@lines) {
        my $rec = eval { $json->decode($line) };
        return undef if $@ || ref $rec ne 'HASH';
        push @out, $rec;
    }
    return undef unless $out[0]{v} && $out[0]{v} == 1;
    for my $rec ( @out[ 1 .. $#out ] ) {
        return undef unless _valid_journal_rel( $rec->{path} );
        return undef unless defined $rec->{from} && defined $rec->{to};
    }
    return \@out;
}

sub _prune_journals {
    my ( $undo_dir, $protect_name ) = @_;
    # Keep the newest 3 journals PER TOOL PREFIX (sorted by the timestamp
    # in the name), and never prune $protect_name (previously all
    # *.jsonl.gz were sorted together, so "bulk-..." sorted before 3
    # "fixhome-..." journals and was deleted right after being written).
    return unless opendir( my $dh, $undo_dir );
    my @names = grep { /\.jsonl\.gz$/ && /-/ } readdir $dh;
    closedir $dh;
    my %by_tool;
    for my $n (@names) {
        my ($prefix) = split /-/, $n, 2;
        push @{ $by_tool{$prefix} }, $n;
    }
    for my $prefix ( keys %by_tool ) {
        my @group = sort {
            my ( undef, $ta ) = split /-/, $a, 2;
            my ( undef, $tb ) = split /-/, $b, 2;
            $ta cmp $tb
        } @{ $by_tool{$prefix} };
        while ( @group > 3 ) {
            my $cand = shift @group;
            next if defined $protect_name && $cand eq $protect_name;
            unlink "$undo_dir/$cand";
        }
    }
    return;
}

sub _write_journal {
    my ( $home, $tool, $changes_ar ) = @_;
    # $changes_ar: arrayref of { rel, from, to } with octal ints.
    return undef unless @{$changes_ar};
    my $undo_dir = _undo_dir($home);
    eval { make_path( $undo_dir, { mode => 0700 } ) };
    return undef if $@;
    my $name = "${tool}-" . _journal_timestamp() . '.jsonl.gz';
    my $path = "$undo_dir/$name";
    my $json = JSON::PP->new();
    my $content =
      $json->encode( { v => 1, tool => $tool, home => $home, scope => $home, started => time() } ) . "\n";
    for my $c ( @{$changes_ar} ) {
        $content .= $json->encode(
            { path => $c->{rel}, from => sprintf( '%04o', $c->{from} ), to => sprintf( '%04o', $c->{to} ) } )
          . "\n";
    }
    if ( !gzip( \$content => $path ) ) {
        return undef;
    }
    _prune_journals( $undo_dir, $name );
    return $name;    # basename for the UI; absolute paths stay server-side
}

sub _journal_history {
    my ( $undo_dir, $prefix ) = @_;
    my @history;
    return \@history unless opendir( my $dh, $undo_dir );
    my @names = sort grep { /^\Q$prefix\E.*\.jsonl\.gz$/ } readdir $dh;
    closedir $dh;
    for my $name ( @names > 3 ? splice @names, -3 : @names ) {
        # Header line only: bulk journals can be huge, never read them whole.
        my $parsed = _read_journal_head("$undo_dir/$name");
        next unless $parsed;
        my $bytes = -s "$undo_dir/$name";
        push @history,
          {
            journal => $name,
            started => $parsed->{started} + 0,
            bytes   => defined $bytes ? $bytes + 0 : 0,
          };
    }
    return \@history;
}

sub _read_journal_head {
    my ($path) = @_;
    my $content;
    return undef unless gunzip( $path => \$content );
    my ($first) = split /\n/, $content, 2;
    return undef unless defined $first && $first ne '';
    my $head = eval { JSON::PP->new()->decode($first) };
    return undef if $@ || ref $head ne 'HASH';
    return undef unless $head->{v} && $head->{v} == 1;
    return $head;
}

sub _restore_path {
    my ( $home, $uid, $rel, $from, $to ) = @_;
    my $path = $rel eq '.' ? $home : "$home/$rel";
    my %out = ( key => $rel, label => $rel, path => $path );
    my @st = lstat $path;    # never follows symlinks
    if ( !@st ) {
        $out{action} = 'missing';
        $out{detail} = __( 'gone since the journal was written; left alone' );
        return \%out;
    }
    if ( -l _ ) {
        $out{action} = 'skipped_symlink';
        $out{detail} = __( 'is a symlink; left alone' );
        return \%out;
    }
    if ( !-f _ && !-d _ ) {
        $out{action} = 'skipped_special';
        $out{detail} = __( 'not a regular file or directory; left alone' );
        return \%out;
    }
    if ( $st[4] != $uid ) {
        $out{action} = 'not_owned';
        $out{detail} = __( 'not owned by you; needs your hosting provider' );
        return \%out;
    }
    my $mode    = $st[2] & 07777;
    my $want_to = oct( '0' . $to );
    if ( $mode != $want_to ) {
        $out{action} = 'changed_since';
        $out{detail} = __( 'mode changed since the journal was written; left alone' );
        return \%out;
    }
    my $target = oct( '0' . $from ) & 0777;    # never restore special bits
    if ( $mode == $target ) {
        $out{action} = 'ok';
        return \%out;
    }
    if ( chmod $target, $path ) {
        $out{action} = 'restored';
        $out{from}   = sprintf( '%04o', $mode );
        $out{to}     = sprintf( '%04o', $target );
    }
    else {
        $out{action} = 'error';
        $out{detail} = __( 'chmod failed: [_1]', "$!" );
    }
    return \%out;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   home_permissions_check - Compare key home paths against their required
#   mode/owner/group and report Current vs Required for each row.
#-------------------------------------------------------------------------------------------------
sub home_permissions_check {
    my ( $args, $result ) = @_;

    my $feature = $FEATURE_FIX_HOME;
    if ( !main::hasfeature($feature) ) {
        $result->error( '_ERROR_FEATURE', $feature );
        return;
    }

    if ( $Cpanel::CPDATA{'DEMO'} ) {
        $result->error( '_ERROR_DEMO_MODE', $feature );
        return;
    }

    if ( $> == 0 ) {
        $result->error('Refusing to run as root.');
        return;
    }

    my ( $user, $uid, $home ) = _caller_info();
    if ( !defined $user || !defined $home || $home eq '' || $home eq '/' ) {
        $result->error('Unable to determine the account home directory.');
        return;
    }

    my $fileprotect_on = _fileprotect_on($home);
    my @rows = map { _check_path( $home, $uid, $_ ) } _required_rows( $user, $fileprotect_on );
    if ( !_has_authorized_keys($home) ) {
        # Small (c): a missing ~/.ssh/authorized_keys is only "needs
        # attention" when the account actually has an SSH key. With no key at
        # all there is nothing to fix, so the row is informational: the page
        # shows a note instead of counting it as a problem.
        # Same for a missing ~/.ssh itself — without a key there is
        # nothing Fix Modes could do with it, so it must not read as a
        # dead-end "will be created" task either.
        for my $row (@rows) {
            if ( $row->{status} eq 'missing'
                && ( $row->{key} eq 'authorized_keys' || $row->{key} eq 'ssh' ) )
            {
                $row->{informational} = 1;
            }
        }
    }
    my $undo_dir  = _undo_dir($home);
    my $latest    = _latest_journal( $undo_dir, 'fixhome-' );
    my $history   = _journal_history( $undo_dir, 'fixhome-' );
    $result->data(
        {
            user           => $user,
            fileprotect    => $fileprotect_on ? 1 : 0,
            rows           => \@rows,
            undo_available => defined $latest ? 1 : 0,
            undo_journal   => defined $latest ? ( split m{/}, $latest )[-1] : undef,
            undo_history   => $history,
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   home_permissions_fix - Fix modes only on the exact key home paths.
#   Never recurses, never follows symlinks, never changes owner/group.
#-------------------------------------------------------------------------------------------------
sub home_permissions_fix {
    my ( $args, $result ) = @_;

    my $feature = $FEATURE_FIX_HOME;
    if ( !main::hasfeature($feature) ) {
        $result->error( '_ERROR_FEATURE', $feature );
        return;
    }

    if ( $Cpanel::CPDATA{'DEMO'} ) {
        $result->error( '_ERROR_DEMO_MODE', $feature );
        return;
    }

    if ( $> == 0 ) {
        $result->error('Refusing to run as root.');
        return;
    }

    my ( $user, $uid, $home ) = _caller_info();
    if ( !defined $user || !defined $home || $home eq '' || $home eq '/' ) {
        $result->error('Unable to determine the account home directory.');
        return;
    }

    my $fileprotect_on = _fileprotect_on($home);
    my @paths = map { _fix_path( $home, $uid, $_ ) } _required_rows( $user, $fileprotect_on );
    my @changes =
      map { { rel => $_->{rel}, from => oct( '0' . $_->{from} ), to => oct( '0' . $_->{to} ) } }
      grep { $_->{action} eq 'fixed' } @paths;
    my $journal = _write_journal( $home, 'fixhome', \@changes );
    _activity_log( $home, 'fix_home', 'fix modes',
        { fixed => scalar(@changes) },
        @changes ? { fn => 'home_permissions_undo', args => {} } : undef );
    $result->data(
        {
            user         => $user,
            fileprotect  => $fileprotect_on ? 1 : 0,
            paths        => \@paths,
            undo_journal => $journal,    # basename or undef; absolute stays server-side
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   home_permissions_undo - Restore modes recorded by the latest Fix Modes run.
#   Same gates as fix (symlinks refused, caller-owned only); protected paths
#   are restored on purpose (that is what undo is for).
#-------------------------------------------------------------------------------------------------
sub home_permissions_undo {
    my ( $args, $result ) = @_;

    my $feature = $FEATURE_FIX_HOME;
    if ( !main::hasfeature($feature) ) {
        $result->error( '_ERROR_FEATURE', $feature );
        return;
    }

    if ( $Cpanel::CPDATA{'DEMO'} ) {
        $result->error( '_ERROR_DEMO_MODE', $feature );
        return;
    }

    if ( $> == 0 ) {
        $result->error('Refusing to run as root.');
        return;
    }

    my ( $user, $uid, $home ) = _caller_info();
    if ( !defined $user || !defined $home || $home eq '' || $home eq '/' ) {
        $result->error('Unable to determine the account home directory.');
        return;
    }

    my $out = _undo_latest( $home, $uid, 'fixhome-' );
    if ( ref $out ne 'HASH' ) {
        $result->error('The latest undo journal is unreadable.');
        return;
    }
    _activity_log( $home, 'fix_home', 'undo fix modes',
        { restored => $out->{restored} // 0 }, undef );
    $out->{user} = $user;
    $result->data($out);
    return 1;
}

# ---------------------------------------------------------------------------
# Bulk Permissions (tool C): detached engine jobs owned by the caller.
# The engine does the walking (unprivileged, same gates as always); this
# module only spawns it, tracks job files under ~/.cpanel/usertools/jobs/,
# and cancels the caller's own job after lock + pid + uid verification.
# ---------------------------------------------------------------------------

sub _jobs_dir {
    my ($home) = @_;
    return "$home/.cpanel/usertools/jobs";
}

sub _valid_job_id {
    my ($id) = @_;
    return ( defined $id && $id =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,64}$/ ) ? $id : undef;
}

sub _job_id_new {
    my ($tool) = @_;
    $tool = 'bulk' unless defined $tool && $tool ne '';
    my @t = gmtime();
    return sprintf( "%s-%04d%02d%02dT%02d%02d%02d-%d-%06d", $tool,
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0], $$, int( rand(1000000) ) );
}

sub _job_paths {
    my ( $home, $id ) = @_;
    return undef unless _valid_job_id($id);
    my $dir = _jobs_dir($home);
    return {
        dir       => $dir,
        meta      => "$dir/$id.job.json",
        progress  => "$dir/$id.progress.json",
        result    => "$dir/$id.result.json",
        stderr    => "$dir/$id.stderr.log",
        log       => "$dir/$id.log",
        recipe    => "$dir/$id.recipe.json",
        cancelled => "$dir/$id.cancelled",
    };
}

sub _job_is_live {
    my ( $dir, $meta ) = @_;
    # Live = pid alive AND no valid final summary yet.
    if ( !$meta->{pid} || !_valid_job_id( $meta->{id} ) ) {
        return 0;
    }
    if ( !kill( 0, $meta->{pid} ) ) {
        return 0;
    }
    my $file = _read_json_file("$dir/$meta->{id}.result.json");
    return ( $file && ref $file->{counts} eq 'HASH' ) ? 0 : 1;
}

sub _find_live_job {
    my ($home) = @_;
    # Newest meta (by mtime) with a live, verified worker pid.
    my $dir = _jobs_dir($home);
    return undef unless opendir( my $dh, $dir );
    my @metas = grep { /\.job\.json$/ } readdir $dh;
    closedir $dh;
    my @with_age =
      map { { name => $_, mtime => ( ( stat("$dir/$_") )[9] // 0 ) } } @metas;
    for my $m ( sort { $b->{mtime} <=> $a->{mtime} } @with_age ) {
        my $meta = _read_json_file("$dir/$m->{name}");
        next unless $meta && $meta->{pid} && $meta->{id};
        next unless kill( 0, $meta->{pid} );
        next unless _proc_owner_ok( $meta->{pid}, $> );
        next unless _proc_is_engine( $meta->{pid} );
        return $meta;
    }
    return undef;
}

sub _prune_jobs {
    my ($home) = @_;
    # Keep the newest 10 finished jobs (all 4 files each). Live jobs are
    # never pruned.
    my $dir = _jobs_dir($home);
    return unless opendir( my $dh, $dir );
    my @metas = grep { /\.job\.json$/ } readdir $dh;
    closedir $dh;
    my @finished;
    for my $m (@metas) {
        my $meta = _read_json_file("$dir/$m");
        next unless $meta && $meta->{id};
        next if _job_is_live( $dir, $meta );
        push @finished,
          { id => $meta->{id}, mtime => ( ( stat("$dir/$m") )[9] // 0 ) };
    }
    @finished = sort { $b->{mtime} <=> $a->{mtime} } @finished;
    splice @finished, 0, 10;    # keep newest 10; rest are stale
    for my $stale (@finished) {
        my $job = _job_paths( $home, $stale->{id} );
        next unless defined $job;
        for my $f ( @{$job}{qw(meta progress result stderr log recipe cancelled)} ) {
            unlink $f;
        }
    }
    return;
}

sub _validate_scope {
    my ( $home, $scope ) = @_;
    # Returns the absolute scope dir, or (undef, reason). Mirrors the
    # engine's own scope rules (defence in depth; the engine re-checks).
    $scope = 'public_html' unless defined $scope && $scope ne '';
    if ( $scope eq 'home' ) {
        return $home;
    }
    my $abs = $scope eq 'public_html' ? "$home/public_html" : $scope;
    if ( $abs !~ m{^/} ) {
        return ( undef, 'scope must be "home", "public_html" or an absolute path' );
    }
    my $real = realpath($abs);
    if ( !defined $real || !-d $real ) {
        return ( undef, 'scope does not exist' );
    }
    if ( $real ne $home && index( $real, "$home/" ) != 0 ) {
        return ( undef, 'scope is outside your home directory' );
    }
    my $hrel = $real eq $home ? '.' : substr( $real, length("$home/") );
    my ($first) = split m{/}, $hrel;
    if ( $first ne '.' && ( $first =~ /^\./ || grep { $_ eq $first } qw(etc mail ssl tmp logs access-logs) ) ) {
        return ( undef, 'scope is inside a protected path and cannot be processed' );
    }
    return $real;
}

sub _read_excludes {
    my ($args) = @_;
    # Primary shape: one `excludes` parameter holding a JSON list. This uses
    # only the documented Cpanel::Args get() method; no multi-value calling
    # convention is assumed. Repeated `exclude`
    # parameters are still accepted for compatibility. Both feed the same
    # validation (max 20, relative, no "..").
    my @collected;
    my ($packed) = $args->get('excludes');
    if ( defined $packed && $packed ne '' ) {
        if ( length($packed) > 8192 ) {
            return ( undef, 'excludes list is too long (max 8 KB)' );
        }
        my $list = eval { JSON::PP->new()->decode($packed) };
        if ($@) {
            return ( undef, 'excludes is not valid JSON' );
        }
        if ( ref $list ne 'ARRAY' ) {
            return ( undef, 'excludes must be a JSON list' );
        }
        for my $e ( @{$list} ) {
            if ( !defined $e ) {
                next;
            }
            if ( ref $e ) {
                return ( undef, 'excludes must contain only strings' );
            }
            push @collected, "$e";
        }
    }
    my @rep = $args->get('exclude');
    for my $e (@rep) {
        if ( ref $e eq 'ARRAY' ) {
            push @collected, map { "$_" } grep { defined $_ } @{$e};
        }
        elsif ( defined $e && $e ne '' ) {
            push @collected, $e;
        }
    }
    return _validate_excludes( \@collected );
}

sub _validate_excludes {
    my ($list) = @_;
    $list = [] unless defined $list;
    if ( ref $list ne 'ARRAY' ) {
        return ( undef, 'excludes must be a list' );
    }
    if ( @{$list} > 20 ) {
        return ( undef, 'too many exclude patterns (max 20)' );
    }
    my @clean;
    for my $pat ( @{$list} ) {
        if ( !defined $pat || $pat !~ /\S/ ) {
            return ( undef, 'empty exclude pattern' );
        }
        $pat =~ s/^\s+|\s+$//g;
        if ( $pat =~ m{^/} ) {
            return ( undef, "exclude must be relative, not absolute: $pat" );
        }
        my @parts = grep { $_ ne '' && $_ ne '.' } split m{/}, $pat;
        if ( grep { $_ eq '..' } @parts ) {
            return ( undef, "exclude must not contain '..': $pat" );
        }
        push @clean, $pat;
    }
    return \@clean;
}

sub _bool_param {
    my ( $value, $default ) = @_;
    # Strict booleans only: missing => default; anything else must be an
    # explicit 1/0/true/false/yes/no/on/off (case-insensitive). In
    # particular the strings "false", "no" and "0" are FALSE (Perl truth
    # would get that wrong). Returns (value) or (undef, reason).
    if ( !defined $value ) {
        return $default;
    }
    my $v = lc $value;
    $v =~ s/^\s+|\s+$//g;
    if ( $v =~ /^(1|true|yes|on)$/ ) {
        return 1;
    }
    if ( $v =~ /^(0|false|no|off)$/ ) {
        return 0;
    }
    return ( undef, "invalid value '$value' (expected 1/0/true/false/yes/no/on/off)" );
}

sub _read_json_file {
    my ($path) = @_;
    open my $fh, '<', $path or return undef;
    local $/;
    my $raw = <$fh>;
    close $fh;
    my $data = eval { JSON::PP->new()->decode($raw) };
    return ( $@ || ref $data ne 'HASH' ) ? undef : $data;
}

sub _engine_running {
    my ($home) = @_;
    # Probe the engine's default single-job lock
    # (~/.cpanel/usertools/perm_engine.lock — must match perm_engine.py).
    # Acquirable => idle. Unreadable => assume running (fail safe).
    my $lock = "$home/.cpanel/usertools/perm_engine.lock";
    my $fh;
    if ( !open $fh, '>>', $lock ) {
        # No directory yet means the engine never ran here: idle. Any other
        # failure is unknown: assume running (fail safe).
        return $!{ENOENT} ? 0 : 1;
    }
    my $busy = flock( $fh, LOCK_EX | LOCK_NB ) ? 0 : 1;
    close $fh;
    return $busy;
}

sub _proc_owner_ok {
    my ( $pid, $uid ) = @_;
    if ( $pid !~ /^\d+$/ ) {
        return 0;
    }
    my $fh;
    if ( !open $fh, '<', "/proc/$pid/status" ) {
        return 0;
    }
    while ( my $line = <$fh> ) {
        if ( $line =~ /^Uid:\s+(\d+)/ ) {
            close $fh;
            return $1 == $uid ? 1 : 0;
        }
    }
    close $fh;
    return 0;
}

sub _proc_is_engine {
    my ($pid) = @_;
    if ( $pid !~ /^\d+$/ ) {
        return 0;
    }
    my $fh;
    if ( !open $fh, '<', "/proc/$pid/cmdline" ) {
        return 0;
    }
    my $cmd = <$fh>;
    close $fh;
    return 0 unless defined $cmd;
    $cmd =~ s/\0/ /g;
    return $cmd =~ /(?:perm_engine|space_cleaner|site_doctor)\.py/ ? 1 : 0;
}

sub _spawn_engine {
    my ( $home, $job, $engine_args, $engine_bin ) = @_;
    # Double-fork + setsid detach. Returns the worker pid or (undef, reason).
    # $engine_bin selects the script (Space Cleaner passes its own);
    # undef keeps the permission engine.
    my ( $rd, $wr );
    if ( !pipe( $rd, $wr ) ) {
        return ( undef, "cannot create pipe: $!" );
    }
    my $kid = fork();
    if ( !defined $kid ) {
        close $rd;
        close $wr;
        return ( undef, "cannot fork: $!" );
    }
    if ( $kid == 0 ) {
        close $rd;
        setsid();
        my $py  = $TEST_ENGINE_BIN // $ENGINE_PYTHON;
        my $bin = $engine_bin // $TEST_ENGINE // $ENGINE_PATH;
        my @cmd = ( $py, $bin, @{$engine_args} );
        if ( ( $ENV{USERTOOLS_TESTING} // '' ) eq '1' && defined $TEST_HOME ) {
            push @cmd, '--home', $home;    # test seam only; never on server
        }
        my $grand = fork();
        if ( !defined $grand ) {
            POSIX::_exit(127);
        }
        if ( $grand == 0 ) {
            close $wr;
            open STDIN,  '<', '/dev/null'   or POSIX::_exit(127);
            open STDOUT, '>', $job->{result} or POSIX::_exit(127);
            open STDERR, '>', $job->{stderr} or POSIX::_exit(127);
            exec { $cmd[0] } @cmd or POSIX::_exit(127);
        }
        print $wr "$grand\n";
        close $wr;
        POSIX::_exit(0);
    }
    close $wr;
    my $line = <$rd>;
    close $rd;
    waitpid( $kid, 0 );
    $line = '' unless defined $line;
    chomp($line);
    if ( $line =~ /^\d+$/ ) {
        return $line;
    }
    return ( undef, 'worker did not start' );
}

sub _gate_tool {
    my ( $result, $feature ) = @_;
    if ( !main::hasfeature($feature) ) {
        $result->error( '_ERROR_FEATURE', $feature );
        return 0;
    }
    if ( $Cpanel::CPDATA{'DEMO'} ) {
        $result->error( '_ERROR_DEMO_MODE', $feature );
        return 0;
    }
    if ( $> == 0 ) {
        $result->error('Refusing to run as root.');
        return 0;
    }
    return 1;
}

sub _gate_caller {
    my ($result) = @_;
    my ( $user, $uid, $home ) = _caller_info();
    if ( !defined $user || !defined $home || $home eq '' || $home eq '/' ) {
        $result->error('Unable to determine the account home directory.');
        return;
    }
    return ( $user, $uid, $home );
}

# ---------------------------------------------------------------------------
# Shared detached-job machinery (Bulk, Ownership Report, Space Cleaner).
# The engine does the walking; these helpers spawn it, track job files,
# report status and cancel. Thin per-tool wrappers validate their own
# options and build engine argv.
# ---------------------------------------------------------------------------

sub _job_status_impl {
    my ( $result, $home, $job_id, $history_prefix ) = @_;
    # Shared status for tools C and D. The caller has already gated.
    # $history_prefix undef skips history.
    my $job = _job_paths( $home, $job_id );
    if ( !defined $job || !-f $job->{meta} ) {
        $result->error('Unknown job.');
        return;
    }
    my $meta = _read_json_file( $job->{meta} );
    if ( !$meta || !$meta->{pid} ) {
        $result->error('Unknown job.');
        return;
    }
    my $progress = _read_json_file( $job->{progress} );
    my $file     = _read_json_file( $job->{result} );
    my $summary  = ( $file && ref $file->{counts} eq 'HASH' ) ? $file : undef;
    my $alive    = kill( 0, $meta->{pid} ) ? 1 : 0;
    my $state    = defined $summary ? 'done' : ( $alive ? 'running' : 'failed' );
    if ( -f $job->{cancelled} ) {
        # Small (a): a job interrupted by Cancel reports 'cancelled', not
        # 'done'/'failed'. The partial summary (if any) still attaches below.
        $state = 'cancelled';
    }
    my $user     = ( _caller_info() )[0];
    my %data = (
        job_id   => $job_id,
        user     => $user,
        state    => $state,
        dry_run  => $meta->{dry_run} ? 1 : 0,
        scope    => $meta->{scope},
        progress => $progress,
        summary  => $summary,
    );
    if ( defined $history_prefix ) {
        $data{history} = _journal_history( _undo_dir($home), $history_prefix );
    }
    $result->data( \%data );
    return 1;
}

sub _job_cancel_impl {
    my ( $result, $home, $uid, $job_id, $tool_label ) = @_;
    # Shared cancel for tools C and D (lock + pid + uid verification).
    # The caller has already gated. $tool_label (e.g. 'bulk_perms')
    # names the product tool for the activity log; callers for
    # read-only scans pass nothing and log nothing.
    my $job = _job_paths( $home, $job_id );
    if ( !defined $job || !-f $job->{meta} ) {
        $result->error('Unknown job.');
        return;
    }
    my $meta = _read_json_file( $job->{meta} );
    if ( !$meta || !$meta->{pid} ) {
        $result->error('Unknown job.');
        return;
    }
    my $pid = $meta->{pid};
    if ( !kill( 0, $pid ) ) {
        $result->data( { job_id => $job_id, cancelled => 0, reason => 'not running (already finished)' } );
        return 1;
    }
    if ( !_proc_owner_ok( $pid, $uid ) ) {
        $result->error('Refusing to stop a process owned by another account.');
        return;
    }
    if ( !_proc_is_engine($pid) ) {
        $result->data( { job_id => $job_id, cancelled => 0, reason => 'not running (stale job)' } );
        return 1;
    }
    if ( !_engine_running($home) ) {
        $result->data( { job_id => $job_id, cancelled => 0, reason => 'not running (already finished)' } );
        return 1;
    }
    kill( 'TERM', $pid );
    for ( 1 .. 20 ) {
        waitpid( $pid, WNOHANG );
        last unless kill( 0, $pid );
        usleep(100000);
    }
    waitpid( $pid, WNOHANG );
    if ( kill( 0, $pid ) ) {
        $result->data( { job_id => $job_id, cancelled => 0, reason => 'still running; try again' } );
        return 1;
    }
    # Small (a): record the interruption so status reports 'cancelled'
    # (same marker file the deploy path uses).
    if ( open my $fh, '>', $job->{cancelled} ) {
        print $fh time(), "\n";
        close $fh;
        chmod 0600, $job->{cancelled};
    }
    if ( defined $tool_label && $tool_label ne '' ) {
        _activity_log( $home, $tool_label, 'cancel job',
            { job_id => $job_id }, undef );
    }
    $result->data( { job_id => $job_id, cancelled => 1 } );
    return 1;
}

sub _job_spawn_and_record {
    my ( $result, $tool, $home, $scope_abs, $excludes, $engine_args, $dry_run, $extra, $engine_bin ) = @_;
    # Shared spawn/grace/meta/prune/answer for tools C and D. The caller has
    # already gated and validated; $engine_args holds the tool-specific argv
    # WITHOUT --json-progress (added here). $extra (optional hashref) merges
    # tool-specific keys into the job meta. $engine_bin (optional) selects
    # the engine script (Space Cleaner); undef keeps the permission engine.

    my $jobs_dir = _jobs_dir($home);
    eval { make_path( $jobs_dir, { mode => 0700 } ) };
    if ($@) {
        $result->error( 'Cannot create job directory: [_1].', "$@" );
        return;
    }
    my $job_id = _job_id_new($tool);
    my $job = _job_paths( $home, $job_id );

    my @full_args = ( @{$engine_args}, '--json-progress', $job->{progress} );
    my ( $pid, $spawn_err ) = _spawn_engine( $home, $job, \@full_args, $engine_bin );
    if ( !defined $pid ) {
        $result->error( 'Cannot start background job: [_1].', $spawn_err );
        return;
    }
    # Grace period: instant tiny jobs may already hold a valid summary.
    usleep(200000);
    my $early   = _read_json_file( $job->{result} );
    my $alive   = kill( 0, $pid ) ? 1 : 0;
    my $summary = ( $early && ref $early->{counts} eq 'HASH' ) ? $early : undef;
    if ( !$alive && !$summary ) {
        $result->raw_error('The background job failed to start. Retry, or contact your host.');
        return;
    }
    my $meta = {
        id => $job_id, pid => $pid + 0, scope => $scope_abs,
        dry_run => $dry_run, tool => $tool,
        excludes => $excludes, started => time(),
        %{ $extra // {} },
    };
    open my $fh, '>', $job->{meta} or do {
        $result->error( 'Cannot record job: [_1].', "$!" );
        return;
    };
    print $fh JSON::PP->new()->encode($meta);
    close $fh;
    _prune_jobs($home);
    $result->data(
        {
            job_id  => $job_id,
            dry_run => $dry_run,
            scope   => $scope_abs,
            state   => defined $summary ? 'done' : 'running',
        }
    );
    return 1;
}

sub _undo_latest {
    my ( $home, $uid, $prefix ) = @_;
    my $latest = _latest_journal( _undo_dir($home), $prefix );
    if ( !defined $latest ) {
        return { paths => [], undo_journal => undef, restored => 0 };
    }
    my $parsed = _read_journal($latest);
    if ( !$parsed ) {
        return ( undef, 'The latest undo journal is unreadable.' );
    }
    my @paths;
    my $restored = 0;
    for my $rec ( @{$parsed}[ 1 .. $#{$parsed} ] ) {
        my $r = _restore_path( $home, $uid, $rec->{path}, $rec->{from}, $rec->{to} );
        $restored++ if $r->{action} eq 'restored';
        push @paths, $r;
    }
    return {
        paths        => \@paths,
        undo_journal => ( split m{/}, $latest )[-1],
        restored     => $restored,
    };
}

#-------------------------------------------------------------------------------------------------
# Name:
#   bulk_permissions_start - Start a detached bulk chmod engine job.
#   Params: scope ("home"|"public_html"|abs path), dry_run (default 1),
#   keep_exec (default 1), harden (default 0), exclude (repeatable).
#-------------------------------------------------------------------------------------------------
sub bulk_permissions_start {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_BULK_PERMS );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($scope_p) = $args->get('scope');
    my ( $scope_abs, $scope_err ) = _validate_scope( $home, $scope_p );
    if ( !defined $scope_abs ) {
        $result->error( 'Invalid scope: [_1].', $scope_err );
        return;
    }
    my ( $excludes, $excl_err ) = _read_excludes($args);
    if ( !defined $excludes ) {
        $result->error( 'Invalid excludes: [_1].', $excl_err );
        return;
    }
    my ($dry_run_p)   = $args->get('dry_run');
    my ($keep_exec_p) = $args->get('keep_exec');
    my ($harden_p)    = $args->get('harden');
    my ( $dry_run, $bool_err ) = _bool_param( $dry_run_p, 1 );
    if ( defined $bool_err ) {
        $result->error( 'Invalid dry_run: [_1].', $bool_err );
        return;
    }
    my ( $keep_exec, $bool_err2 ) = _bool_param( $keep_exec_p, 1 );
    if ( defined $bool_err2 ) {
        $result->error( 'Invalid keep_exec: [_1].', $bool_err2 );
        return;
    }
    my ( $harden, $bool_err3 ) = _bool_param( $harden_p, 0 );
    if ( defined $bool_err3 ) {
        $result->error( 'Invalid harden: [_1].', $bool_err3 );
        return;
    }

    if ( _engine_running($home) ) {
        # A job is already running: reattach instead of spawning into the
        # engine's exit-3 path, so the page shows progress, not an error.
        my $live = _find_live_job($home);
        $result->data(
            {
                state  => 'busy',
                job_id => defined $live ? $live->{id} : undef,
                $live
                ? ( scope => $live->{scope}, dry_run => $live->{dry_run} ? 1 : 0 )
                : (),
            }
        );
        return 1;
    }

    my @engine_args = (
        'chmod', '--scope', $scope_abs,
        ( $dry_run ? '--dry-run' : () ),
        ( $keep_exec ? '--keep-exec' : '--no-keep-exec' ),
        ( $harden    ? '--harden-sensitive' : () ),
        # Single argv element per exclude: a value starting with '-' can
        # never be mistaken for a flag.
        ( map { '--exclude=' . $_ } @{$excludes} ),
    );
    return _job_spawn_and_record(
        $result, 'bulk', $home, $scope_abs, $excludes, \@engine_args,
        $dry_run, { keep_exec => $keep_exec, harden => $harden } );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   bulk_permissions_status - Progress JSON plus the final summary for a job.
#-------------------------------------------------------------------------------------------------
sub bulk_permissions_status {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_BULK_PERMS );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my $ok = _job_status_impl( $result, $home, $job_id, 'bulk-' );
    _activity_log_job_done(
        $home, 'bulk_perms', $job_id,
        sub {
            my ( $summary, $meta ) = @_;
            return undef unless ( $meta->{tool} // '' ) eq 'bulk';
            return ( $summary->{counts}{changed} // 0 ) > 0
              ? { fn => 'bulk_permissions_undo', args => {} }
              : undef;
        }
    );
    return $ok;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   bulk_permissions_cancel - SIGTERM the caller's own job only. The target
#   must be alive, owned by the caller, look like our engine, and hold the
#   single-job lock; anything else is refused or reported as finished.
#-------------------------------------------------------------------------------------------------
sub bulk_permissions_cancel {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_BULK_PERMS );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_cancel_impl( $result, $home, $uid, $job_id, 'bulk_perms' );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   bulk_permissions_undo - Restore modes from the latest bulk journal.
#-------------------------------------------------------------------------------------------------
sub bulk_permissions_undo {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_BULK_PERMS );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    # Small (d): undo runs as a background job like apply (47k paths can take
    # seconds inside UAPI otherwise). Resolve + validate the journal
    # synchronously (instant), then spawn the engine's `undo --journal` with
    # --json-progress; progress/cancel ride the usual status/cancel calls and
    # the engine summary carries the restored counts.
    my $latest = _latest_journal( _undo_dir($home), 'bulk-' );
    if ( !defined $latest ) {
        $result->data(
            {
                user => $user, state => 'done', paths => [],
                undo_journal => undef, restored => 0,
            }
        );
        return 1;
    }
    my $parsed = _read_journal($latest);
    if ( !$parsed ) {
        $result->error('The latest undo journal is unreadable.');
        return;
    }
    if ( _engine_running($home) ) {
        my $live = _find_live_job($home);
        $result->data(
            {
                state  => 'busy',
                job_id => defined $live ? $live->{id} : undef,
                $live ? ( scope => $live->{scope} ) : (),
            }
        );
        return 1;
    }
    my ($journal_name) = ( split m{/}, $latest )[-1];
    return _job_spawn_and_record(
        $result, 'undo', $home, $home, [], [ 'undo', '--journal', $latest ],
        0, { undo_journal => $journal_name } );
}

# ---------------------------------------------------------------------------
# Manage Shell (tool A): thin UAPI wrappers around the privileged Admin
# module. All shell changes happen in Cpanel::Admin::Modules::UserTools::Shell
# (root, no paths, caller identity only). These wrappers only gate, forward
# exactly {mode}, and add the key-presence check read as the user.
# ---------------------------------------------------------------------------

sub _has_authorized_keys {
    my ($home) = @_;
    # 1 if ~/.ssh/authorized_keys exists as a regular file with at least one
    # non-blank, non-comment line. Symlinks and unreadable files count as no.
    my $path = "$home/.ssh/authorized_keys";
    my @st = lstat $path;
    if ( !@st || -l _ ) {
        return 0;
    }
    my $fh;
    if ( !open $fh, '<', $path ) {
        return 0;
    }
    while ( my $line = <$fh> ) {
        $line =~ s/^\s+|\s+$//g;
        if ( $line ne '' && $line !~ /^#/ ) {
            close $fh;
            return 1;
        }
    }
    close $fh;
    return 0;
}

sub _adminbin_reply {
    # Single wrapper for the plugin's AdminBin call sites: cPanel itself
    # refuses adminbin fetches for SUSPENDED accounts before our admin module
    # runs ("... not allowed for suspended accounts at .../Server.pm line
    # 87"), so Base::_gate_account's suspension check never sees the call —
    # the refusal arrives as a transport die. Absorb the die into the
    # { error => ... } reply shape every call site already handles. Always
    # returns a HASHREF.
    my ( $mod, $action, $args_hr ) = @_;
    my $reply =
      eval { Cpanel::AdminBin::Call::call( 'UserTools', $mod, $action, defined $args_hr ? $args_hr : () ) };
    return $reply if ref $reply eq 'HASH';
    if ( my $ex = $@ ) {
        my $text = ref $ex ? ( defined $ex->{error} ? $ex->{error} : "$ex" ) : $ex;
        return { error => $text };
    }
    return { error => 'adminbin reply was not a hash' };
}

sub _is_suspended_error {
    # The suspension refusal is cPanel's own; match it by its text.
    my ($err) = @_;
    return ( defined $err && $err =~ /suspend/i ) ? 1 : 0;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   shell_status - Current shell state plus key presence for the caller.
#-------------------------------------------------------------------------------------------------
sub shell_status {
    my ( $args, $result ) = @_;

    my $feature = $FEATURE_SHELL;
    if ( !main::hasfeature($feature) ) {
        $result->error( '_ERROR_FEATURE', $feature );
        return;
    }

    if ( $Cpanel::CPDATA{'DEMO'} ) {
        $result->error( '_ERROR_DEMO_MODE', $feature );
        return;
    }

    if ( $> == 0 ) {
        $result->error('Refusing to run as root.');
        return;
    }

    my ( $user, $uid, $home ) = _caller_info();
    if ( !defined $user || !defined $home || $home eq '' || $home eq '/' ) {
        $result->error('Unable to determine the account home directory.');
        return;
    }

    my $admin = _adminbin_reply( 'Shell', 'GET_SHELL' );
    if ( my $err = $admin->{error} ) {
        if ( _is_suspended_error($err) ) {
            $result->error('Your account is suspended; shell changes are unavailable.');
            return;
        }
        ( my $plain = $err ) =~ s/\.\z//;
        $result->error( 'Shell state error: [_1].', $plain );
        return;
    }
    $result->data(
        {
            %{$admin},
            user                => $user,
            has_authorized_keys => _has_authorized_keys($home),
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   shell_set - Request a shell mode change. Only `mode` is read; every other
#   request parameter is ignored here and rejected by the Admin module.
#-------------------------------------------------------------------------------------------------
sub shell_set {
    my ( $args, $result ) = @_;

    my $feature = $FEATURE_SHELL;
    if ( !main::hasfeature($feature) ) {
        $result->error( '_ERROR_FEATURE', $feature );
        return;
    }

    if ( $Cpanel::CPDATA{'DEMO'} ) {
        $result->error( '_ERROR_DEMO_MODE', $feature );
        return;
    }

    if ( $> == 0 ) {
        $result->error('Refusing to run as root.');
        return;
    }

    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($mode) = $args->get('mode');
    if ( !defined $mode || ( $mode ne 'disabled' && $mode ne 'jailed' && $mode ne 'normal' ) ) {
        $result->error( 'Invalid mode: [_1].', defined $mode ? $mode : '' );
        return;
    }

    my $admin = _adminbin_reply( 'Shell', 'SET_SHELL', { mode => $mode } );
    if ( my $err = $admin->{error} ) {
        if ( _is_suspended_error($err) ) {
            $result->error('Your account is suspended; shell changes are unavailable.');
            return;
        }
        ( my $plain = $err ) =~ s/\.\z//;
        $result->error( 'Shell change error: [_1].', $plain );
        return;
    }
    $result->data($admin);
    _activity_log( $home, 'shell', 'set mode', { mode => $mode }, undef );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   ownership_report_start - Start a detached read-only ownership scan.
#   Params: scope ("home"|"public_html"|abs path), excludes (JSON list or
#   repeatable). Read-only: the report never changes anything, so there is
#   no dry run and no undo.
#-------------------------------------------------------------------------------------------------
sub ownership_report_start {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_OWNERSHIP_REPORT );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($scope_p) = $args->get('scope');
    my ( $scope_abs, $scope_err ) = _validate_scope( $home, $scope_p );
    if ( !defined $scope_abs ) {
        $result->error( 'Invalid scope: [_1].', $scope_err );
        return;
    }
    my ( $excludes, $excl_err ) = _read_excludes($args);
    if ( !defined $excludes ) {
        $result->error( 'Invalid excludes: [_1].', $excl_err );
        return;
    }

    if ( _engine_running($home) ) {
        my $live = _find_live_job($home);
        $result->data(
            {
                state  => 'busy',
                job_id => defined $live ? $live->{id} : undef,
                $live ? ( scope => $live->{scope} ) : (),
            }
        );
        return 1;
    }

    my @engine_args = (
        'report', '--scope', $scope_abs,
        ( map { '--exclude=' . $_ } @{$excludes} ),
    );
    return _job_spawn_and_record(
        $result, 'report', $home, $scope_abs, $excludes, \@engine_args, 0 );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   ownership_report_status - Progress JSON plus the final report summary.
#-------------------------------------------------------------------------------------------------
sub ownership_report_status {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_OWNERSHIP_REPORT );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_status_impl( $result, $home, $job_id, undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   ownership_report_cancel - Stop the caller's own scan (same verification
#   as bulk cancel).
#-------------------------------------------------------------------------------------------------
sub ownership_report_cancel {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_OWNERSHIP_REPORT );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_cancel_impl( $result, $home, $uid, $job_id );
}

# ---------------------------------------------------------------------------
# Space Cleaner: reclaim disk space and inodes, with trash and restore.
# The scan and the clean each run as a detached engine job (same
# single-job lock as the permission engine), reusing the spawn, status
# and cancel helpers above. Trash listing, restore and empty run
# synchronously: they only touch the caller's own trash folder, whose
# batch ids come from the server-side listing (never paths from the
# request). Like every tool, Space Cleaner is gated by its Feature
# Manager feature plus the enable_space_cleaner policy key.
# ---------------------------------------------------------------------------

sub _space_policy_enabled {
    my ($result) = @_;
    # Off by default: the WHM policy must explicitly say 1, like the
    # enable_* switches of the other tools.
    my $policy = _read_user_policy();
    if ( ref $policy eq 'HASH'
        && ( $policy->{enable_space_cleaner} // '' ) eq '1' )
    {
        return 1;
    }
    $result->error('This feature is not enabled for your account.');
    return 0;
}

sub _space_categories_param {
    my ( $args, $require ) = @_;
    # Primary shape: one `categories` parameter holding a JSON list.
    # Repeated `category` parameters are accepted for compatibility.
    my @collected;
    my ($packed) = $args->get('categories');
    if ( defined $packed && $packed ne '' ) {
        if ( length($packed) > 1024 ) {
            return ( undef, 'categories list is too long' );
        }
        my $list = eval { JSON::PP->new()->decode($packed) };
        if ($@) {
            return ( undef, 'categories is not valid JSON' );
        }
        if ( ref $list ne 'ARRAY' ) {
            return ( undef, 'categories must be a JSON list' );
        }
        push @collected, @{$list};
    }
    my @rep = $args->get('category');
    for my $e (@rep) {
        if ( ref $e eq 'ARRAY' ) {
            push @collected, grep { defined $_ } @{$e};
        }
        elsif ( defined $e && $e ne '' ) {
            push @collected, $e;
        }
    }
    my %valid = map { $_ => 1 } @SPACE_CATEGORIES;
    my @clean;
    for my $c (@collected) {
        if ( !defined $c || !$valid{$c} ) {
            return ( undef, "unknown category: $c" );
        }
        push @clean, $c unless grep { $_ eq $c } @clean;
    }
    if ( $require && !@clean ) {
        return ( undef, 'choose at least one category' );
    }
    return ( \@clean, undef );
}

sub _space_start_busy {
    my ( $result, $home ) = @_;
    # A job is already running: reattach instead of spawning into the
    # engine's exit-3 path, so the page shows progress, not an error.
    my $live = _find_live_job($home);
    $result->data(
        {
            state  => 'busy',
            job_id => defined $live ? $live->{id} : undef,
            $live ? ( categories => $live->{categories} ) : (),
        }
    );
    return 1;
}

sub _space_engine_args {
    my ($categories) = @_;
    my @engine_args =
      ( map { '--category=' . $_ } @{$categories} );
    if ( defined $TEST_POLICY_FILE ) {
        push @engine_args, '--policy', $TEST_POLICY_FILE;
    }
    return @engine_args;
}

sub _space_engine_bin {
    return $TEST_SPACE_ENGINE // $SPACE_ENGINE_PATH;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_scan_start - Preview what could be reclaimed (changes nothing
#   except pruning trash batches older than the policy).
#-------------------------------------------------------------------------------------------------
sub space_scan_start {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ( $categories, $cat_err ) = _space_categories_param( $args, 0 );
    if ( !defined $categories ) {
        $result->error( 'Invalid categories: [_1].', $cat_err );
        return;
    }
    if ( !@{$categories} ) {
        $categories = [@SPACE_CATEGORIES];
    }
    if ( _engine_running($home) ) {
        return _space_start_busy( $result, $home );
    }

    my @engine_args = ( 'clean-scan', _space_engine_args($categories) );
    return _job_spawn_and_record(
        $result, 'space-scan', $home, $home, [], \@engine_args,
        1, { categories => $categories }, _space_engine_bin() );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_scan_status - Progress JSON plus the final scan summary.
#-------------------------------------------------------------------------------------------------
sub space_scan_status {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_status_impl( $result, $home, $job_id, undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_scan_cancel - Stop the caller's own scan (same verification as
#   the other cancel calls).
#-------------------------------------------------------------------------------------------------
sub space_scan_cancel {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_cancel_impl( $result, $home, $uid, $job_id );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_clean_start - Move candidates to the trash, truncate big logs
#   and delete the plugin's own old files (explicit categories required).
#-------------------------------------------------------------------------------------------------
sub space_clean_start {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ( $categories, $cat_err ) = _space_categories_param( $args, 1 );
    if ( !defined $categories ) {
        $result->error( 'Invalid categories: [_1].', $cat_err );
        return;
    }
    if ( _engine_running($home) ) {
        return _space_start_busy( $result, $home );
    }

    my @engine_args = ( 'clean-run', _space_engine_args($categories) );
    return _job_spawn_and_record(
        $result, 'space-clean', $home, $home, [], \@engine_args,
        0, { categories => $categories }, _space_engine_bin() );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_clean_status - Progress JSON plus the final clean summary.
#-------------------------------------------------------------------------------------------------
sub space_clean_status {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my $ok = _job_status_impl( $result, $home, $job_id, undef );
    _activity_log_job_done(
        $home, 'space_cleaner', $job_id,
        sub {
            my ( $summary, $meta ) = @_;
            return undef unless ( $meta->{tool} // '' ) eq 'space-clean';
            return defined $summary->{trash_batch}
              ? { fn => 'space_trash_restore',
                  args => { batch => $summary->{trash_batch} } }
              : undef;
        }
    );
    return $ok;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_clean_cancel - Stop the caller's own clean run.
#-------------------------------------------------------------------------------------------------
sub space_clean_cancel {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_cancel_impl( $result, $home, $uid, $job_id, 'space_cleaner' );
}

sub _space_valid_batch {
    my ($batch) = @_;
    return ( defined $batch && $batch =~ /^[0-9]{8}T[0-9]{6}$/ ) ? $batch : undef;
}

sub _space_trash_entries {
    my ( $home, $batch ) = @_;
    # (bytes, files): regular files under one batch, never following links.
    my $root  = "$home/.usertools-trash/$batch";
    my $total = 0;
    my $files = 0;
    my @stack = ($root);
    while (@stack) {
        my $cur = pop @stack;
        my @st = lstat $cur;
        next unless @st;
        if ( -l _ ) {
            next;
        }
        if ( -d _ ) {
            my $dh;
            if ( !opendir( $dh, $cur ) ) {
                next;
            }
            while ( my $name = readdir $dh ) {
                next if $name eq '.' || $name eq '..';
                push @stack, "$cur/$name";
            }
            closedir $dh;
            next;
        }
        if ( -f _ ) {
            $total += $st[7];
            $files++;
        }
    }
    return ( $total, $files );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_trash_list - Trash batches with sizes (synchronous, read-only).
#-------------------------------------------------------------------------------------------------
sub space_trash_list {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my $trash = "$home/.usertools-trash";
    my @batches;
    if ( opendir( my $dh, $trash ) ) {
        while ( my $name = readdir $dh ) {
            next unless _space_valid_batch($name);
            my $dir = "$trash/$name";
            my @st = lstat $dir;
            next unless @st && !-l _ && -d _;
            my ( $bytes, $files ) = _space_trash_entries( $home, $name );
            push @batches,
              {
                batch   => $name,
                created => $st[9],
                bytes   => $bytes + 0,
                files   => $files + 0,
              };
        }
        closedir $dh;
    }
    @batches = sort { $b->{batch} cmp $a->{batch} } @batches;
    my $total = 0;
    $total += $_->{bytes} for @batches;
    $result->data(
        {
            batches       => \@batches,
            trash_bytes   => $total + 0,
            trash_batches => scalar(@batches) + 0,
        }
    );
    return 1;
}

sub _run_space_sync {
    my ( $home, $args ) = @_;
    # Run the Space Cleaner engine synchronously (restore/empty only touch
    # the caller's own trash folder, so no detached job is needed). Returns
    # the decoded summary or (undef, reason).
    my $py  = $TEST_ENGINE_BIN // $ENGINE_PYTHON;
    my $bin = $TEST_SPACE_ENGINE // $SPACE_ENGINE_PATH;
    my @cmd = ( $py, $bin, @{$args} );
    if ( ( $ENV{USERTOOLS_TESTING} // '' ) eq '1' && defined $TEST_HOME ) {
        push @cmd, '--home', $home;
    }
    if ( defined $TEST_POLICY_FILE ) {
        push @cmd, '--policy', $TEST_POLICY_FILE;
    }
    my $env = {
        PATH               => '/usr/bin:/bin',
        USERTOOLS_TESTING  => ( $ENV{USERTOOLS_TESTING} // '' ),
    };
    my $run = _spawn_sync( \@cmd, $home, $env, 300, 1048576 );
    if ( !$run || $run->{error} ) {
        return ( undef, $run ? $run->{error} : 'could not start the engine' );
    }
    if ( $run->{timed_out} ) {
        return ( undef, 'the engine run timed out' );
    }
    if ( $run->{exit} != 0 ) {
        return ( undef, 'the engine run failed' );
    }
    my $summary = eval { JSON::PP->new()->decode( $run->{output} ) };
    if ( $@ || ref $summary ne 'HASH' ) {
        return ( undef, 'the engine returned an unreadable summary' );
    }
    return ( $summary, undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_trash_restore - Put one trash batch back (conflicts reported,
#   never overwritten).
#-------------------------------------------------------------------------------------------------
sub space_trash_restore {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($batch_p) = $args->get('batch');
    my $batch = _space_valid_batch($batch_p);
    if ( !defined $batch ) {
        $result->error('Invalid batch: pick one from the trash list.');
        return;
    }
    my ( $summary, $err ) =
      _run_space_sync( $home, [ 'trash-restore', '--batch', $batch ] );
    if ( !defined $summary ) {
        $result->error( 'Restore failed: [_1].', $err );
        return;
    }
    my $counts = $summary->{counts} || {};
    _activity_log( $home, 'space_cleaner', 'restore trash batch',
        { batch => $batch, restored => $counts->{restored_files} + 0 },
        undef );
    $result->data(
        {
            batch     => $batch,
            restored  => $counts->{restored_files} + 0,
            conflicts => $counts->{restore_conflicts} + 0,
            state     => 'done',
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   space_trash_empty - Delete one batch or every batch (cannot be undone).
#-------------------------------------------------------------------------------------------------
sub space_trash_empty {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SPACE_CLEANER );
    return unless _space_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($batch_p) = $args->get('batch');
    my @engine_args = ('trash-empty');
    my $which;
    if ( !defined $batch_p || $batch_p eq '' || $batch_p eq 'all' ) {
        push @engine_args, '--all';
        $which = 'all';
    }
    else {
        my $batch = _space_valid_batch($batch_p);
        if ( !defined $batch ) {
            $result->error('Invalid batch: pick one from the trash list.');
            return;
        }
        push @engine_args, '--batch', $batch;
        $which = $batch;
    }
    my ( $summary, $err ) = _run_space_sync( $home, \@engine_args );
    if ( !defined $summary ) {
        $result->error( 'Empty failed: [_1].', $err );
        return;
    }
    my $counts = $summary->{counts} || {};
    _activity_log( $home, 'space_cleaner', 'empty trash',
        { batch => $which, emptied => $counts->{changed} + 0 }, undef );
    $result->data(
        {
            emptied => $counts->{changed} + 0,
            batch   => $which,
            state   => 'done',
        }
    );
    return 1;
}

# ---------------------------------------------------------------------------
# Site Doctor + Exposed Files Scanner: read-only website checks with
# probed findings, plus server-derived fixes (commented php_value lines,
# quarantine moves, marked deny blocks), every one with preview or an
# existing-file undo. Probes go to the account's own address with the
# domain as Host (never through public DNS); writes never take paths
# from the request (domain names resolve server-side, finding ids resolve
# against the stored scan). Both tools are off by default: Feature
# Manager feature plus enable_site_doctor / enable_exposed_files.
# ---------------------------------------------------------------------------

our $SITE_MAX_DOMAINS = 10;
our $SITE_BUDGET_SECONDS = 30;
our $SITE_TIMEOUT_SECONDS = 5;

sub _site_policy_enabled {
    my ( $result, $key ) = @_;
    # Off by default: the WHM policy must explicitly say 1.
    my $policy = _read_user_policy();
    if ( ref $policy eq 'HASH' && ( $policy->{$key} // '' ) eq '1' ) {
        return 1;
    }
    $result->error('This feature is not enabled for your account.');
    return 0;
}

sub _site_engine_bin {
    return $TEST_SITE_ENGINE // $SITE_ENGINE_PATH;
}

sub _site_targets {
    my ($user) = @_;
    # Server-side website list with probe addresses. DomainInfo first
    # (ip and port travel with each record); the userdata files as
    # fallback (ip:/port: lines when present).
    my @out;
    my $data = _call_uapi( 'DomainInfo', 'domains_data' );
    if ( ref $data eq 'HASH' ) {
        my $d = ref $data->{result} eq 'HASH' ? $data->{result}{data} : $data->{data};
        my @recs;
        if ( ref $d eq 'HASH' ) {
            push @recs, $d->{main_domain} if ref $d->{main_domain} eq 'HASH';
            for my $k (qw(addon_domains sub_domains parked_domains alias_domains)) {
                push @recs, @{ $d->{$k} } if ref $d->{$k} eq 'ARRAY';
            }
        }
        elsif ( ref $d eq 'ARRAY' ) {
            @recs = @{$d};
        }
        my %seen;
        for my $r (@recs) {
            next unless ref $r eq 'HASH';
            next unless defined $r->{domain} && defined $r->{documentroot};
            next if $seen{ lc( $r->{domain} ) }++;
            my %t = ( domain => $r->{domain}, documentroot => $r->{documentroot} );
            $t{ip} = $r->{ip} if defined $r->{ip} && $r->{ip} ne '';
            if ( defined $r->{port} && $r->{port} =~ /^\d+$/ ) {
                $t{port} = $r->{port} + 0;
            }
            push @out, \%t;
        }
    }
    if ( !@out ) {
        my $base = defined $TEST_DOMAIN_DATA_DIR ? $TEST_DOMAIN_DATA_DIR : '/var/cpanel/userdata';
        my $dir = "$base/$user";
        my $dh;
        if ( opendir( $dh, $dir ) ) {
            for my $f ( sort grep { -f "$dir/$_" } readdir $dh ) {
                next if $f eq 'main' || $f eq 'cache' || $f =~ /^\./;
                next if $f =~ /(?:_SSL|\.cache|\.json|\.yaml)$/ || $f =~ /\.php-fpm\./;
                next unless $f =~ /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
                my ( $docroot, $ip, $port );
                if ( open my $fh, '<', "$dir/$f" ) {
                    while ( my $line = <$fh> ) {
                        $docroot = $1 if !defined $docroot && $line =~ /^\s*documentroot:\s*(\S+)\s*$/;
                        $ip      = $1 if !defined $ip      && $line =~ /^\s*ip:\s*(\S+)\s*$/;
                        $port    = $1 if !defined $port    && $line =~ /^\s*port:\s*(\d+)\s*$/;
                    }
                    close $fh;
                }
                next unless defined $docroot;
                my %t = ( domain => $f, documentroot => $docroot );
                $t{ip}   = $ip if defined $ip;
                $t{port} = $port + 0 if defined $port;
                push @out, \%t;
            }
            closedir $dh;
        }
    }
    if ( defined $TEST_SITE_IP_OVERRIDE ) {
        $_->{ip} = $TEST_SITE_IP_OVERRIDE for @out;
    }
    if ( defined $TEST_SITE_PORT_OVERRIDE ) {
        $_->{port} = $TEST_SITE_PORT_OVERRIDE + 0 for @out;
    }
    return @out;
}

sub _site_php_map {
    my ($user) = @_;
    # lc(host) => { version => 'NN' (ea-phpNN digits or undef), fpm => 0/1 }.
    # The fpm flag is the server-side handler answer: never guess it from
    # the .htaccess handler block. Unknown shapes contribute nothing.
    my %map;
    my $data = _fetch_langphp_data($user);
    _collect_site_php( $data, \%map );
    return \%map;
}

sub _collect_site_php {
    my ( $node, $map ) = @_;
    if ( ref $node eq 'HASH' ) {
        my ($dkey) = grep { /^(?:domain|vhost|servername)$/i } keys %{$node};
        if ( defined $dkey && !ref $node->{$dkey} ) {
            my ($host) = $node->{$dkey} =~ /(\S+)/;
            if ( defined $host ) {
                my ($vkey) = grep { /^(?:php_version|version|php)$/i } keys %{$node};
                my $ver;
                if ( defined $vkey && !ref $node->{$vkey} ) {
                    ($ver) = $node->{$vkey} =~ /ea-php(\d\d)/;
                }
                my ($fkey) = grep { /^php_fpm$/i } keys %{$node};
                my $has_info = ( defined $ver || defined $fkey ) ? 1 : 0;
                if ($has_info) {
                    $map->{ lc $host } = {
                        version => $ver,
                        fpm     => ( defined $fkey && $node->{$fkey} ) ? 1 : 0,
                    };
                }
            }
        }
        for my $v ( values %{$node} ) {
            _collect_site_php( $v, $map ) if ref $v;
        }
    }
    elsif ( ref $node eq 'ARRAY' ) {
        for my $v ( @{$node} ) {
            _collect_site_php( $v, $map ) if ref $v;
        }
    }
    return;
}

sub _site_domain_rec {
    my ( $user, $domain, $targets_ar ) = @_;
    # Server-side allowlist: the requested domain must be one of the
    # account's own. Returns the record or (undef, reason).
    return ( undef, 'choose one of your websites' )
      unless defined $domain && $domain ne '';
    my @targets = defined $targets_ar ? @{$targets_ar} : _site_targets($user);
    for my $t (@targets) {
        next unless ref $t eq 'HASH';
        if ( defined $t->{domain} && lc( $t->{domain} ) eq lc($domain) ) {
            return ( $t, undef );
        }
    }
    return ( undef, 'unknown website' );
}

sub _doctor_verdicts {
    my ( $rec, $php ) = @_;
    # One plain-words line per finding, plus an attention flag the page
    # uses for its banner. Pure function of the engine facts (isolated
    # for tests); $php is {version, fpm}.
    $php = {} unless ref $php eq 'HASH';
    my @lines;
    my $attention = 0;
    my $say = sub { push @lines, $_[0]; $attention = 1 if $_[1]; };
    my $domain = $rec->{domain} // '?';
    if ( $rec->{deferred} ) {
        return { lines => ["$domain was not checked ($rec->{reason})."], attention => 1 };
    }
    my $http = ref $rec->{http} eq 'HASH' ? $rec->{http} : {};
    my $status = $http->{status} // 0;
    if ( !$status ) {
        $say->( "$domain did not answer: the connection failed "
          . "(the site may be down, or its DNS may not point here yet).", 1 );
    }
    elsif ( $status == 200 ) {
        my $ms = defined $http->{ms} ? " in $http->{ms} ms" : "";
        push @lines, "$domain loads (HTTP 200$ms).";
    }
    elsif ( $status >= 300 && $status < 400 ) {
        my $loc = $http->{location} // 'elsewhere';
        $say->("$domain redirects (HTTP $status to $loc); "
          . "only the first redirect is shown, it is not followed.", 1);
    }
    elsif ( $status == 403 ) {
        $say->("$domain is forbidden (HTTP 403): check the .htaccess "
          . "deny rules and the folder permissions.", 1);
    }
    elsif ( $status == 404 ) {
        $say->("$domain returns not found (HTTP 404): check the "
          . "document root and the default page.", 1);
    }
    elsif ( $status >= 500 ) {
        $say->("$domain returns a server error (HTTP $status): "
          . "check the error log below.", 1);
    }
    else {
        $say->("$domain answered HTTP $status.", 1);
    }
    my $doc = ref $rec->{docroot} eq 'HASH' ? $rec->{docroot} : {};
    if ( !$doc->{usable} ) {
        $say->( "Document root problem: $doc->{reason}.", 1 );
        return { lines => \@lines, attention => $attention };
    }
    if ( !$doc->{index} ) {
        $say->("No index page found (index.html, index.htm or index.php).", 1);
    }
    if ( defined $doc->{mode} && $doc->{expected_mode} && $doc->{mode} ne $doc->{expected_mode} ) {
        $say->("Document root permissions are $doc->{mode}, expected $doc->{expected_mode}.", 1);
    }
    if ( $doc->{owner_ok} ? 0 : 1 ) {
        $say->("Document root is not owned by you.", 1);
    }
    my $ht = ref $rec->{htaccess} eq 'HASH' ? $rec->{htaccess} : {};
    if ( $ht->{present} ) {
        my @php_lines = ref $ht->{php_value_lines} eq 'ARRAY' ? @{ $ht->{php_value_lines} } : ();
        if ( @php_lines && $php->{fpm} ) {
            $say->("The .htaccess sets php_value/php_flag lines ("
              . join( ', ', @php_lines )
              . "), which PHP-FPM rejects: comment them out or the site "
              . "returns 500.", 1);
        }
        elsif (@php_lines) {
            $say->("The .htaccess sets php_value/php_flag lines ("
              . join( ', ', @php_lines ) . ").", 1);
        }
        if ( $ht->{missing_rewrite_engine} ) {
            $say->("The .htaccess has rewrite rules but no "
              . "RewriteEngine On: the rules do nothing.", 1);
        }
    }
    else {
        push @lines, "No .htaccess in the document root.";
    }
    my $ssl = ref $rec->{ssl} eq 'HASH' ? $rec->{ssl} : {};
    if ( $ssl->{ok} ) {
        my $days = $ssl->{days_left} // 0;
        if ( $days < 0 ) {
            $say->("The TLS certificate expired " . ( -$days ) . " days ago.", 1);
        }
        elsif ( $days <= 30 ) {
            $say->("The TLS certificate expires in $days days.", 1);
        }
        else {
            push @lines, "The TLS certificate is valid ($days days left).";
        }
    }
    else {
        $say->( "The TLS certificate could not be checked"
          . ( defined $ssl->{error} ? " ($ssl->{error})." : "." ), 1 );
    }
    return { lines => \@lines, attention => $attention };
}

sub _run_site_sync {
    my ( $home, $args ) = @_;
    # Run the site engine synchronously (quarantine move/restore touch one
    # finding at a time, so no detached job is needed). Returns the decoded
    # summary or (undef, reason).
    my $py  = $TEST_ENGINE_BIN // $ENGINE_PYTHON;
    my $bin = $TEST_SITE_ENGINE // $SITE_ENGINE_PATH;
    my @cmd = ( $py, $bin, @{$args} );
    if ( ( $ENV{USERTOOLS_TESTING} // '' ) eq '1' && defined $TEST_HOME ) {
        push @cmd, '--home', $home;
    }
    my $env = {
        PATH           => '/usr/bin:/bin',
        USERTOOLS_TESTING => ( $ENV{USERTOOLS_TESTING} // '' ),
    };
    my $run = _spawn_sync( \@cmd, $home, $env, 300, 1048576 );
    if ( !$run || $run->{error} ) {
        return ( undef, $run ? $run->{error} : 'could not start the engine' );
    }
    if ( $run->{timed_out} ) {
        return ( undef, 'the engine run timed out' );
    }
    if ( $run->{exit} != 0 ) {
        return ( undef, 'the engine run failed' );
    }
    my $summary = eval { JSON::PP->new()->decode( $run->{output} ) };
    if ( $@ || ref $summary ne 'HASH' ) {
        return ( undef, 'the engine returned an unreadable summary' );
    }
    return ( $summary, undef );
}

sub _site_targets_argv {
    my ( $targets, $php_map, $want_php ) = @_;
    # Server-side targets to engine --target flags (joined with "|",
    # which domains and absolute paths can never contain unescaped).
    my @argv;
    for my $t ( @{$targets} ) {
        next unless defined $t->{domain} && defined $t->{documentroot};
        next unless defined $t->{ip} && defined $t->{port};
        my @parts = ( $t->{domain}, $t->{documentroot}, $t->{ip}, $t->{port} );
        if ($want_php) {
            my $php = ref $php_map eq 'HASH' ? $php_map->{ lc( $t->{domain} ) } : undef;
            push @parts, ( ref $php eq 'HASH' && defined $php->{version} ) ? "ea-php$php->{version}" : 'unknown';
            push @parts, ( ref $php eq 'HASH' && $php->{fpm} ) ? '1' : '0';
        }
        push @argv, ( '--target', join( '|', @parts ) );
    }
    return @argv;
}

sub _site_scan_busy {
    my ( $result, $home ) = @_;
    # A job is already running: reattach instead of spawning into the
    # engine's exit-3 path, so the page shows progress, not an error.
    my $live = _find_live_job($home);
    $result->data(
        {
            state  => 'busy',
            job_id => defined $live ? $live->{id} : undef,
        }
    );
    return 1;
}

sub _site_scan_start {
    my ( $result, $home, $user, $tool ) = @_;
    # Shared scan start for Site Doctor and the Exposed Files Scanner.
    # The caller has already gated (feature + policy). Domains come from
    # the server-side list; the engine resolves nothing from the request.
    my $want_php = $tool eq 'doctor-scan' ? 1 : 0;
    my @targets = _site_targets($user);
    if ( !@targets ) {
        $result->error('Cannot list domains for this account, so nothing was checked.');
        return;
    }
    if ( _engine_running($home) ) {
        return _site_scan_busy( $result, $home );
    }
    my @engine_args = ( $tool eq 'doctor-scan' ? 'doctor-scan' : 'exposed-scan',
        _site_targets_argv( \@targets, _site_php_map($user), $want_php ),
        '--timeout', $SITE_TIMEOUT_SECONDS, '--budget', $SITE_BUDGET_SECONDS );
    if ( defined $TEST_POLICY_FILE ) {
        push @engine_args, '--policy', $TEST_POLICY_FILE;
    }
    return _job_spawn_and_record(
        $result, $tool, $home, $home, [], \@engine_args,
        1, {}, _site_engine_bin() );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   doctor_scan_start - Check homepages, docroots, TLS and error logs
#   (up to 10 domains inside a 30 s budget; the rest are deferred).
#-------------------------------------------------------------------------------------------------
sub doctor_scan_start {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SITE_DOCTOR );
    return unless _site_policy_enabled( $result, 'enable_site_doctor' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    return _site_scan_start( $result, $home, $user, 'doctor-scan' );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   doctor_scan_status - Progress JSON plus the fact records and verdicts.
#-------------------------------------------------------------------------------------------------
sub doctor_scan_status {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SITE_DOCTOR );
    return unless _site_policy_enabled( $result, 'enable_site_doctor' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my $job = _job_paths( $home, $job_id );
    if ( !defined $job || !-f $job->{meta} ) {
        $result->error('Unknown job.');
        return;
    }
    my $meta = _read_json_file( $job->{meta} );
    if ( !$meta || !$meta->{pid} ) {
        $result->error('Unknown job.');
        return;
    }
    my $progress = _read_json_file( $job->{progress} );
    my $file     = _read_json_file( $job->{result} );
    my $summary  = ( $file && ref $file->{counts} eq 'HASH' ) ? $file : undef;
    my $alive    = kill( 0, $meta->{pid} ) ? 1 : 0;
    my $state = defined $summary ? 'done' : ( $alive ? 'running' : 'failed' );
    if ( -f $job->{cancelled} ) {
        $state = 'cancelled';
    }
    my %data = (
        job_id => $job_id, user => $user, state => $state,
        dry_run => 1, progress => $progress, summary => $summary,
    );
    if ( defined $summary && ref $summary->{domains} eq 'ARRAY' ) {
        my $php_map = _site_php_map($user);
        my $fileprotect = _fileprotect_on($home);
        my @with_verdicts;
        for my $rec ( @{ $summary->{domains} } ) {
            next unless ref $rec eq 'HASH';
            my %r = %{$rec};
            if ( ref $r{docroot} eq 'HASH' && $r{docroot}{usable} ) {
                my $is_pub = defined $r{docroot}{abs} && $r{docroot}{abs} eq "$home/public_html";
                $r{docroot} = {
                    %{ $r{docroot} },
                    expected_mode => ( $fileprotect && $is_pub ) ? '0750' : '0755',
                };
            }
            my $php = $php_map->{ lc( $rec->{domain} // '' ) };
            my $v = _doctor_verdicts( \%r, $php );
            my %out = ( %r, verdict => $v->{lines},
                attention => $v->{attention} ? 1 : 0 );
            if ( ref $r{htaccess} eq 'HASH'
                && ref $r{htaccess}{php_value_lines} eq 'ARRAY'
                && @{ $r{htaccess}{php_value_lines} }
                && ref $php eq 'HASH' && $php->{fpm} )
            {
                # The page's Fix button appears only for this case.
                $out{fix_php_lines} = $r{htaccess}{php_value_lines};
            }
            push @with_verdicts, \%out;
        }
        $data{summary} = { %{$summary}, domains => \@with_verdicts };
    }
    $result->data( \%data );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   doctor_scan_cancel - Stop the caller's own scan (same verification as
#   the other cancel calls).
#-------------------------------------------------------------------------------------------------
sub doctor_scan_cancel {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SITE_DOCTOR );
    return unless _site_policy_enabled( $result, 'enable_site_doctor' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_cancel_impl( $result, $home, $uid, $job_id );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_scan_start - Walk every docroot and probe risky names.
#-------------------------------------------------------------------------------------------------
sub exposed_scan_start {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    return _site_scan_start( $result, $home, $user, 'exposed-scan' );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_scan_status - Progress JSON plus findings with exposed flags.
#-------------------------------------------------------------------------------------------------
sub exposed_scan_status {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_status_impl( $result, $home, $job_id, undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_scan_cancel - Stop the caller's own scan.
#-------------------------------------------------------------------------------------------------
sub exposed_scan_cancel {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    return _job_cancel_impl( $result, $home, $uid, $job_id );
}

sub _ht_named_section {
    my ( $content, $begin, $end, $lines_ar ) = @_;
    # Insert or replace ONE named marked section (see _ht_merge for the
    # shared unnamed one); an empty replacement drops the section.
    # Everything outside the markers keeps its bytes and order.
    $content = '' unless defined $content;
    $lines_ar = [] unless ref $lines_ar eq 'ARRAY';
    my @lines = split( /\n/, $content );
    my ( $bi, $ei );
    for my $i ( 0 .. $#lines ) {
        if ( !defined $bi && $lines[$i] eq $begin ) {
            $bi = $i;
        }
        if ( $lines[$i] eq $end ) {
            $ei = $i;
        }
    }
    my @section;
    if ( @{$lines_ar} ) {
        @section = ( $begin, @{$lines_ar}, $end );
    }
    if ( defined $bi && defined $ei && $ei > $bi ) {
        splice @lines, $bi, $ei - $bi + 1, @section;
    }
    elsif (@section) {
        if ( @lines && $lines[-1] ne '' ) {
            push @lines, '';
        }
        push @lines, @section;
    }
    my $out = join( "\n", @lines );
    $out =~ s/\n{3,}/\n\n/g;
    $out .= "\n" if $out ne '' && substr( $out, -1 ) ne "\n";
    return $out;
}

sub _ht_section_rules {
    my ( $content, $begin, $end ) = @_;
    # Raw lines currently inside a named marked section (no markers).
    $content = '' unless defined $content;
    my @lines = split( /\n/, $content );
    my ( $bi, $ei );
    for my $i ( 0 .. $#lines ) {
        if ( !defined $bi && $lines[$i] eq $begin ) {
            $bi = $i;
        }
        if ( $lines[$i] eq $end ) {
            $ei = $i;
        }
    }
    return [] unless defined $bi && defined $ei && $ei > $bi;
    return [ @lines[ $bi + 1 .. $ei - 1 ] ];
}

our $HT_DOC_BEGIN = '# BEGIN UserTools Site Doctor';
our $HT_DOC_END   = '# END UserTools Site Doctor';
our $HT_EXP_BEGIN = '# BEGIN UserTools Exposed Files';
our $HT_EXP_END   = '# END UserTools Exposed Files';

sub _expose_safe_path {
    my ($s) = @_;
    # Printable ASCII only, without `"`, `'`, backslash or backtick: a
    # quote would close the rule's quoting and anything outside
    # printable ASCII (controls, DEL, newlines, non-ASCII bytes) could
    # smuggle extra lines into the file, either of which makes Apache
    # reject the whole .htaccess (site down). True when $s may be
    # embedded in a deny rule.
    return 0 unless defined $s && $s ne '';
    return $s =~ /\A[\x20\x21\x23-\x26\x28-\x5B\x5D-\x5F\x61-\x7E]+\z/ ? 1 : 0;
}

sub _expose_rule_lines {
    my ( $relpath, $kind, $urlpath, $abspath ) = @_;
    # One deny rule keyed by the exact home-relative path. The match
    # runs against what Apache mapped the request to (REQUEST_FILENAME,
    # an absolute filesystem path), not the URL: trailing slashes,
    # doubled slashes and path info never reach the filename, so URL
    # variants of the same file cannot dodge the rule. Dies before
    # building anything when a name is unsafe for the file.
    for my $s ( $relpath, $urlpath, $abspath ) {
        die "unsafe path for .htaccess rule\n"
          unless _expose_safe_path($s);
    }
    my $esc = $abspath;
    $esc =~ s/([\\^\$.|?*+()\[\]{}])/\\$1/g;
    $esc =~ s/#/[#]/g;
    my @out = (
        "# path: $relpath",
        "# url: $urlpath",
        "# Exposed Files: deny $relpath ($kind)",
    );
    if ( $kind eq 'git_dir' ) {
        push @out, "<If \"%{REQUEST_FILENAME} =~ m#^$esc/#\">";
    }
    else {
        push @out, "<If \"%{REQUEST_FILENAME} == '$abspath'\">";
    }
    push @out, '    Require all denied', '</If>';
    return @out;
}

sub _expose_block_lines {
    my (@rules) = @_;
    # Full section body for a set of [relpath, kind, urlpath, abspath]
    # quads, each rule traceable to its path so unblock removes exactly
    # one rule.
    my @lines = ('# Managed by UserTools Exposed Files: deny direct access',
                 '# to files that must never be public. One rule per finding;',
                 '# removing a rule restores access to that path only.');
    for my $r (@rules) {
        push @lines, '', _expose_rule_lines( @{$r} );
    }
    return \@lines;
}

sub _expose_parse_rules {
    my ($lines_ar) = @_;
    # Section body back into [relpath, kind, urlpath] triples, pairing
    # each `# path:` marker (plus its `# url:` line) with the rule
    # comment that follows it. Sections written before the url line
    # existed yield an undef urlpath; the caller heals those from the
    # docroot before rebuilding.
    my @rules;
    my ( $pending_rel, $pending_url );
    for my $ln ( @{$lines_ar} ) {
        if ( $ln =~ /^# path: (\S+)\s*$/ ) {
            ( $pending_rel, $pending_url ) = ( $1, undef );
            next;
        }
        if ( defined $pending_rel && $ln =~ /^# url: (.+?)\s*$/ ) {
            $pending_url = $1;
            next;
        }
        if ( defined $pending_rel && $ln =~ /^# Exposed Files: deny \S+ \((.*)\)\s*$/ ) {
            push @rules, [ $pending_rel, $1, $pending_url ];
            ( $pending_rel, $pending_url ) = ( undef, undef );
        }
    }
    return \@rules;
}

sub _expose_rule_abspath {
    my ( $home, $real, $configured, $rel ) = @_;
    # Absolute path as Apache sees it (REQUEST_FILENAME): prefer the
    # vhost-configured docroot string (filenames use the path as
    # configured, not the resolved one), else the resolved docroot.
    # Returns undef when the finding is not under a known docroot.
    for my $base ( $configured, $real ) {
        next unless defined $base && $base ne '';
        ( my $norm = $base ) =~ s{/+\z}{};
        my $prefix = '';
        if ( $norm eq $home ) {
            $prefix = '';
        }
        elsif ( index( $norm, "$home/" ) == 0 ) {
            $prefix = substr( $norm, length("$home/") );
        }
        else {
            next;
        }
        next if $rel eq '' || $rel eq '.';
        if ( $prefix eq '' || index( $rel, "$prefix/" ) == 0 ) {
            my $rest = $prefix eq '' ? $rel
              : substr( $rel, length($prefix) + 1 );
            next if $rest eq '' || $rest =~ m{(?:^|/)\.\.(?:/|$)};
            return "$norm/$rest";
        }
    }
    return undef;
}

sub _expose_heal_urlpaths {
    my ( $rules, $home, $real, $configured ) = @_;
    # Fill urlpaths (pre-url-line sections) from the docroot, and the
    # absolute match path for every rule; abspath prefers the
    # vhost-configured docroot string.
    my $prefix = $real;
    $prefix =~ s{^\Q$home/\E}{};
    for my $r ( @{$rules} ) {
        if ( !defined $r->[2] ) {
            my $rel = $r->[0];
            if ( $prefix ne '' && index( $rel, "$prefix/" ) == 0 ) {
                $r->[2] = '/' . substr( $rel, length($prefix) + 1 );
            }
            else {
                $r->[2] = '/' . $rel;
            }
        }
        if ( !defined $r->[3] ) {
            $r->[3] = _expose_rule_abspath( $home, $real, $configured,
                $r->[0] );
        }
    }
    return;
}

sub _doctor_htaccess_plan {
    my ( $domain, $real ) = @_;
    # Preview plan for commenting out php_value/php_flag lines in one
    # docroot .htaccess. $real is the resolved, home-confined docroot.
    # Returns (plan) or (undef, reason). The file is read fresh here.
    return ( undef, 'unknown website' ) unless defined $domain;
    my $path = "$real/.htaccess";
    my $current = eval { _read_text_file($path) };
    if ($@) {
        return ( undef, "cannot read the .htaccess file: $@" );
    }
    $current = '' unless defined $current;
    my @lines = split( /\n/, $current );
    # Only unguarded lines count: cPanel wraps its own php_value lines in
    # <IfModule phpX_module>/<IfModule lsapi_module> blocks, which Apache
    # skips under PHP-FPM, so those never 500. A negated guard does not
    # protect (its body runs exactly when the module is absent).
    my @php;
    my @guards;
    for my $i ( 0 .. $#lines ) {
        my $code = $lines[$i];
        $code =~ s/#.*$//;
        if ( $code =~ m{^\s*</IfModule\b}i ) {
            pop @guards if @guards;
            next;
        }
        if ( $code =~ m{^\s*<IfModule\s+(!?)\s*([\w:.-]+)\s*>}i ) {
            push @guards, $1 ? 0 : 1;
            next;
        }
        next if $code =~ /^\s*</;
        if ( $code =~ /^\s*(?:php_value|php_flag)\b/i ) {
            push @php, $i + 1 unless grep { $_ } @guards;
        }
    }
    if ( !@php ) {
        return ( undef, 'no php_value or php_flag lines left to fix' );
    }
    if ( grep { $_ eq $HT_DOC_BEGIN } @lines ) {
        return ( undef, 'a Site Doctor block is already applied' );
    }
    my %drop = map { $_ => 1 } @php;
    my @kept;
    my @moved;
    for my $i ( 0 .. $#lines ) {
        if ( $drop{ $i + 1 } ) {
            push @moved, '# ' . $lines[$i];
        }
        else {
            push @kept, $lines[$i];
        }
    }
    my @section = (
        $HT_DOC_BEGIN,
        '# Disabled by Site Doctor: PHP-FPM rejects php_value/php_flag lines',
        '# in .htaccess (they cause HTTP 500). Originals below, commented out.',
        @moved,
        $HT_DOC_END,
    );
    my $new = @kept ? join( "\n", @kept ) . "\n" : "";
    $new .= "\n" if $new ne "";
    $new .= join( "\n", @section ) . "\n";
    return (
        {
            domain => $domain,
            path   => $path,
            lines  => \@php,
            new    => $new,
            diff   => _ht_diff( $current, $new ),
        },
        undef
    );
}

sub _doctor_job_domains {
    my ( $home, $job_id ) = @_;
    # Domains enumerated by a finished doctor scan (server-side only).
    my $job = _job_paths( $home, _valid_job_id($job_id) // '' );
    return undef unless defined $job && -f $job->{result};
    my $file = _read_json_file( $job->{result} );
    return undef unless $file && ref $file->{domains} eq 'ARRAY';
    return $file->{domains};
}

sub _doctor_docroot {
    my ( $home, $user, $job_id, $domain ) = @_;
    # The docroot a Site Doctor htaccess call may touch: the domain must
    # have been scanned (job membership) and still belong to the account
    # (live server-side lookup), resolved and home-confined.
    my $domains = _doctor_job_domains( $home, $job_id );
    return ( undef, 'Unknown job.' ) unless defined $domains;
    my ($found) = grep { ref $_ eq 'HASH' && defined $_->{domain} && $_->{domain} eq $domain } @{$domains};
    return ( undef, 'Unknown website for this scan.' ) unless defined $found;
    my ( $rec, $err ) = _site_domain_rec( $user, $domain );
    return ( undef, $err ) unless defined $rec;
    my $real = Cwd::realpath( $rec->{documentroot} );
    if ( !defined $real || !-d $real ) {
        return ( undef, 'the document root is missing' );
    }
    if ( $real ne $home && index( $real, "$home/" ) != 0 ) {
        return ( undef, 'the document root is outside your home folder' );
    }
    return ( $real, undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   doctor_htaccess_preview - Show what commenting out the php_value lines
#   would change (changes nothing).
#-------------------------------------------------------------------------------------------------
sub doctor_htaccess_preview {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SITE_DOCTOR );
    return unless _site_policy_enabled( $result, 'enable_site_doctor' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my ($domain) = $args->get('domain');
    my ( $real, $docroot_err ) = _doctor_docroot( $home, $user, $job_id, $domain );
    if ( !defined $real ) {
        if ( $docroot_err eq 'Unknown job.' || $docroot_err eq 'Unknown website for this scan.' ) {
            $result->error($docroot_err);
        }
        else {
            $result->error( 'Nothing to fix: [_1].', $docroot_err );
        }
        return;
    }
    my ( $plan, $err ) = _doctor_htaccess_plan( $domain, $real );
    if ( !defined $plan ) {
        $result->error( 'Nothing to fix: [_1].', $err );
        return;
    }
    $result->data(
        {
            domain => $plan->{domain},
            file   => '.htaccess',
            lines  => $plan->{lines},
            diff   => $plan->{diff},
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   doctor_htaccess_fix - Comment out php_value/php_flag lines (backup kept).
#-------------------------------------------------------------------------------------------------
sub doctor_htaccess_fix {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SITE_DOCTOR );
    return unless _site_policy_enabled( $result, 'enable_site_doctor' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my ($domain) = $args->get('domain');
    my ( $real, $docroot_err ) = _doctor_docroot( $home, $user, $job_id, $domain );
    if ( !defined $real ) {
        if ( $docroot_err eq 'Unknown job.' || $docroot_err eq 'Unknown website for this scan.' ) {
            $result->error($docroot_err);
        }
        else {
            $result->error( 'Nothing to fix: [_1].', $docroot_err );
        }
        return;
    }
    my ( $plan, $err ) = _doctor_htaccess_plan( $domain, $real );
    if ( !defined $plan ) {
        $result->error( 'Nothing to fix: [_1].', $err );
        return;
    }
    if ( !_ht_ensure_orig( $home, $plan->{path} ) ) {
        $result->error('Could not preserve the original .htaccess; nothing was changed.');
        return;
    }
    my $bak = _ht_backup( $plan->{path} );
    if ( !defined $bak ) {
        $result->error('Could not back up the .htaccess; nothing was changed.');
        return;
    }
    if ( !_write_text_file( $plan->{path}, $plan->{new}, 0644 ) ) {
        _ht_restore_exact( $plan->{path}, $bak );
        $result->error('Could not write the .htaccess file; the backup was restored.');
        return;
    }
    _activity_log( $home, 'site_doctor', 'fix .htaccess',
        { domain => $domain, lines => scalar( @{ $plan->{lines} } ) },
        { fn => 'doctor_htaccess_undo',
          args => { job_id => $job_id, domain => $domain } } );
    $result->data(
        {
            domain => $plan->{domain},
            file   => '.htaccess',
            lines  => $plan->{lines},
            backup => $bak,
            diff   => $plan->{diff},
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   doctor_htaccess_undo - Restore the newest backup of that .htaccess.
#-------------------------------------------------------------------------------------------------
sub doctor_htaccess_undo {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_SITE_DOCTOR );
    return unless _site_policy_enabled( $result, 'enable_site_doctor' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my ($domain) = $args->get('domain');
    my ( $real, $docroot_err ) = _doctor_docroot( $home, $user, $job_id, $domain );
    if ( !defined $real ) {
        $result->error($docroot_err);
        return;
    }
    my $path = "$real/.htaccess";
    my @cands = grep { -f $_ } glob "$path.usertools-bak-*";
    if ( !@cands ) {
        $result->error('No backup found: nothing to undo.');
        return;
    }
    @cands = sort { ( ( stat($b) )[9] // 0 ) <=> ( ( stat($a) )[9] // 0 ) } @cands;
    if ( rename( $cands[0], $path ) ) {
        chmod 0644, $path;
        _activity_log( $home, 'site_doctor', 'undo .htaccess fix',
            { domain => $domain }, undef );
        $result->data( { domain => $domain, restored => 1 } );
        return 1;
    }
    $result->error('Could not restore the backup.');
    return;
}

sub _exposed_findings {
    my ( $home, $job_id ) = @_;
    # Findings recorded by a finished exposed scan (server-side only).
    my $job = _job_paths( $home, _valid_job_id($job_id) // '' );
    return ( undef, 'Unknown job.' ) unless defined $job && -f $job->{result};
    my $file = _read_json_file( $job->{result} );
    return ( undef, 'Unknown job.' )
      unless $file && ref $file->{findings} eq 'ARRAY';
    return ( $file->{findings}, undef );
}

sub _exposed_resolve {
    my ( $home, $job_id, $finding_id ) = @_;
    # Finding ids come from the scan (f1, f2, ...); anything else is refused
    # before any path is touched. The relpath is revalidated home-relative.
    if ( !defined $finding_id || $finding_id !~ /^[a-z0-9]{1,16}$/ ) {
        return ( undef, 'Unknown finding.' );
    }
    my ( $findings, $err ) = _exposed_findings( $home, $job_id );
    return ( undef, $err ) unless defined $findings;
    for my $f ( @{$findings} ) {
        next unless ref $f eq 'HASH' && defined $f->{id} && $f->{id} eq $finding_id;
        my $rel = $f->{relpath} // '';
        $rel =~ s{^/+}{};
        $rel =~ s{/\z}{};
        if ( $rel eq '' || $rel eq '.' || $rel =~ m{(?:^|/)\.\.(?:/|$)} ) {
            return ( undef, 'Unknown finding.' );
        }
        my %copy = %{$f};
        $copy{relpath} = $rel;
        return ( \%copy, undef );
    }
    return ( undef, 'Unknown finding.' );
}

sub _exposed_reprobe {
    my ( $home, $ip, $port, $host, $urlpath ) = @_;
    # Re-probe one URL path after an action via the site engine (single,
    # tested prober: HEAD then a capped GET, status + exposed only, never
    # the body).
    if ( defined $TEST_EXPOSED_PROBE ) {
        return { %{$TEST_EXPOSED_PROBE} };
    }
    return { status => 0, exposed => 0 }
      unless defined $home && defined $ip && defined $port
      && defined $host && defined $urlpath;
    my ( $summary, undef ) = _run_site_sync(
        $home,
        [ 'exposed-reprobe', '--ip', $ip, '--port', $port,
          '--host', $host, '--path', $urlpath ] );
    if ( ref $summary eq 'HASH' && ref $summary->{probe} eq 'HASH' ) {
        my $p = $summary->{probe};
        return {
            status  => $p->{status} // 0,
            exposed => $p->{exposed} ? 1 : 0,
        };
    }
    return { status => 0, exposed => 0 };
}

sub _quarantine_list {
    my ($home) = @_;
    my $root = "$home/.usertools-quarantine";
    my @batches;
    if ( opendir( my $dh, $root ) ) {
        while ( my $name = readdir $dh ) {
            next unless $name =~ /^[0-9]{8}T[0-9]{6}$/;
            my $dir = "$root/$name";
            my @st = lstat $dir;
            next unless @st && !-l _ && -d _;
            my @entries;
            eval {
                open my $mfh, '<', "$dir/manifest.json" or die "no manifest\n";
                local $/;
                my $raw = <$mfh>;
                close $mfh;
                my $data = JSON::PP->new()->decode( $raw // '' );
                if ( ref $data eq 'HASH' && ref $data->{entries} eq 'ARRAY' ) {
                    for my $e ( @{ $data->{entries} } ) {
                        push @entries, $e->{path} if ref $e eq 'HASH' && defined $e->{path};
                    }
                }
            };
            my $bytes = 0;
            my $files = 0;
            my @stack = ($dir);
            while (@stack) {
                my $cur = pop @stack;
                my @cst = lstat $cur;
                next unless @cst;
                next if -l _;
                if ( -d _ ) {
                    if ( opendir( my $sdh, $cur ) ) {
                        while ( my $n = readdir $sdh ) {
                            next if $n eq '.' || $n eq '..';
                            push @stack, "$cur/$n";
                        }
                        closedir $sdh;
                    }
                    next;
                }
                if ( -f _ ) {
                    $bytes += $cst[7];
                    $files++;
                }
            }
            push @batches,
              { batch => $name, created => $st[9], bytes => $bytes + 0,
                files => $files + 0, entries => \@entries };
        }
        closedir $dh;
    }
    @batches = sort { $b->{batch} cmp $a->{batch} } @batches;
    return \@batches;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_move - Quarantine one finding out of the public folder.
#-------------------------------------------------------------------------------------------------
sub exposed_move {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my ($finding_id) = $args->get('finding');
    my ( $finding, $err ) = _exposed_resolve( $home, $job_id, $finding_id );
    if ( !defined $finding ) {
        $result->error( 'Unknown finding.' );
        return;
    }
    my ( $summary, $run_err ) = _run_site_sync(
        $home, [ 'exposed-move', '--job', $job_id, '--finding', $finding_id ] );
    if ( !defined $summary ) {
        $result->error( 'Move failed: [_1].', $run_err );
        return;
    }
    my ($rec) = _site_domain_rec( $user, $finding->{domain} );
    my $reprobe = { status => 0, exposed => 0 };
    if ( defined $rec && defined $rec->{ip} && defined $rec->{port} ) {
        my $upath = $finding->{urlpath} // ( '/' . ( $finding->{relpath} // '' ) );
        $reprobe = _exposed_reprobe( $home, $rec->{ip}, $rec->{port}, $finding->{domain}, $upath );
    }
    _activity_log( $home, 'exposed_files', 'quarantine finding',
        { finding => $finding_id, batch => $summary->{quarantine_batch} },
        defined $summary->{quarantine_batch}
        ? { fn => 'exposed_restore',
            args => { batch => $summary->{quarantine_batch} } }
        : undef );
    $result->data(
        {
            finding  => $finding_id,
            moved    => $summary->{counts}{moved} ? 1 : 0,
            batch    => $summary->{quarantine_batch},
            reprobed => $reprobe,
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_restore - Put a whole quarantine batch back.
#-------------------------------------------------------------------------------------------------
sub exposed_restore {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($batch_p) = $args->get('batch');
    my $batch = ( defined $batch_p && $batch_p =~ /^[0-9]{8}T[0-9]{6}$/ ) ? $batch_p : undef;
    if ( !defined $batch ) {
        $result->error('Invalid batch: pick one from the quarantine list.');
        return;
    }
    my ( $summary, $err ) = _run_site_sync( $home, [ 'exposed-restore', '--batch', $batch ] );
    if ( !defined $summary ) {
        $result->error( 'Restore failed: [_1].', $err );
        return;
    }
    _activity_log( $home, 'exposed_files', 'restore quarantine batch',
        { batch => $batch,
          restored => $summary->{counts}{restored} + 0,
          conflicts => $summary->{counts}{restore_conflicts} + 0 },
        undef );
    $result->data(
        {
            batch     => $batch,
            restored  => $summary->{counts}{restored} + 0,
            conflicts => $summary->{counts}{restore_conflicts} + 0,
            state     => 'done',
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_quarantine_list - Quarantine batches with their entries.
#-------------------------------------------------------------------------------------------------
sub exposed_quarantine_list {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my $batches = _quarantine_list($home);
    my $total = 0;
    $total += $_->{bytes} for @{$batches};
    $result->data(
        {
            batches         => $batches,
            quarantine_bytes  => $total + 0,
            quarantine_batches => scalar( @{$batches} ) + 0,
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_block - Deny one finding with a marked .htaccess block.
#-------------------------------------------------------------------------------------------------
sub exposed_block {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my ($finding_id) = $args->get('finding');
    my ( $finding, $err ) = _exposed_resolve( $home, $job_id, $finding_id );
    if ( !defined $finding ) {
        $result->error('Unknown finding.');
        return;
    }
    my ( $rec, $rec_err ) = _site_domain_rec( $user, $finding->{domain} );
    if ( !defined $rec ) {
        $result->error( $rec_err );
        return;
    }
    my $real = realpath( $rec->{documentroot} );
    if ( !defined $real || !-d $real || ( $real ne $home && index( $real, "$home/" ) != 0 ) ) {
        $result->error('The document root is unusable.');
        return;
    }
    my $path = "$real/.htaccess";
    my $current = eval { _read_text_file($path) };
    if ($@) {
        $result->error( 'Cannot read the .htaccess file.' );
        return;
    }
    $current = '' unless defined $current;
    my $rules = _expose_parse_rules( _ht_section_rules( $current, $HT_EXP_BEGIN, $HT_EXP_END ) );
    _expose_heal_urlpaths( $rules, $home, $real, $rec->{documentroot} );
    my $upath = $finding->{urlpath} // ( '/' . ( $finding->{relpath} // '' ) );
    my $abspath = _expose_rule_abspath( $home, $real, $rec->{documentroot},
        $finding->{relpath} );
    if ( !defined $abspath ) {
        $result->error('Cannot block this file: it is not under the website folder.');
        return;
    }
    push @{$rules}, [ $finding->{relpath}, $finding->{kind}, $upath, $abspath ]
      unless grep { $_->[0] eq $finding->{relpath} } @{$rules};
    my $lines = eval { _expose_block_lines( @{$rules} ) };
    if ( $@ || !$lines ) {
        $result->error('Cannot block this file: its name is unsafe for .htaccess rules. Move it out of the public folder instead.');
        return;
    }
    my $new = _ht_named_section( $current, $HT_EXP_BEGIN, $HT_EXP_END, $lines );
    if ( !$new || $new eq $current ) {
        $result->data( { finding => $finding_id, blocked => 0, note => 'already blocked' } );
        return 1;
    }
    if ( !_ht_ensure_orig( $home, $path ) ) {
        $result->error('Could not preserve the original .htaccess; nothing was changed.');
        return;
    }
    my $bak = _ht_backup($path);
    if ( !defined $bak ) {
        $result->error('Could not back up the .htaccess; nothing was changed.');
        return;
    }
    if ( !_write_text_file( $path, $new, 0644 ) ) {
        $result->error('Could not write the .htaccess file.');
        return;
    }
    my $reprobe = { status => 0, exposed => 0 };
    if ( defined $rec->{ip} && defined $rec->{port} ) {
        my $upath = $finding->{urlpath} // ( '/' . ( $finding->{relpath} // '' ) );
        $reprobe = _exposed_reprobe( $home, $rec->{ip}, $rec->{port}, $finding->{domain}, $upath );
    }
    _activity_log( $home, 'exposed_files', 'block finding',
        { finding => $finding_id },
        { fn => 'exposed_unblock',
          args => { job_id => $job_id, finding => $finding_id } } );
    $result->data(
        {
            finding  => $finding_id,
            blocked  => 1,
            reprobed => $reprobe,
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   exposed_unblock - Remove one finding's deny rule again.
#-------------------------------------------------------------------------------------------------
sub exposed_unblock {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_EXPOSED_FILES );
    return unless _site_policy_enabled( $result, 'enable_exposed_files' );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my ($finding_id) = $args->get('finding');
    my ( $finding, $err ) = _exposed_resolve( $home, $job_id, $finding_id );
    if ( !defined $finding ) {
        $result->error('Unknown finding.');
        return;
    }
    my ( $rec, $rec_err ) = _site_domain_rec( $user, $finding->{domain} );
    if ( !defined $rec ) {
        $result->error( $rec_err );
        return;
    }
    my $real = realpath( $rec->{documentroot} );
    if ( !defined $real || !-d $real || ( $real ne $home && index( $real, "$home/" ) != 0 ) ) {
        $result->error('The document root is unusable.');
        return;
    }
    my $path = "$real/.htaccess";
    my $current = eval { _read_text_file($path) };
    if ($@) {
        $result->error('Cannot read the .htaccess file.');
        return;
    }
    $current = '' unless defined $current;
    my $rules = _expose_parse_rules( _ht_section_rules( $current, $HT_EXP_BEGIN, $HT_EXP_END ) );
    my @kept = grep { $_->[0] ne $finding->{relpath} } @{$rules};
    if ( @kept == @{$rules} ) {
        $result->data( { finding => $finding_id, unblocked => 0, note => 'no rule for this finding' } );
        return 1;
    }
    _expose_heal_urlpaths( \@kept, $home, $real, $rec->{documentroot} );
    my $kept_lines = eval { _expose_block_lines(@kept) };
    if ( $@ || ( @kept && !$kept_lines ) ) {
        $result->error('Cannot rewrite the deny rules: a listed name is unsafe for .htaccess rules.');
        return;
    }
    my $new = _ht_named_section( $current, $HT_EXP_BEGIN, $HT_EXP_END,
        @kept ? $kept_lines : [] );
    if ( !_ht_ensure_orig( $home, $path ) ) {
        $result->error('Could not preserve the original .htaccess; nothing was changed.');
        return;
    }
    my $bak = _ht_backup($path);
    if ( !defined $bak ) {
        $result->error('Could not back up the .htaccess; nothing was changed.');
        return;
    }
    if ( !_write_text_file( $path, $new, 0644 ) ) {
        $result->error('Could not write the .htaccess file.');
        return;
    }
    my $reprobe = { status => 0, exposed => 0 };
    if ( defined $rec->{ip} && defined $rec->{port} ) {
        my $upath = $finding->{urlpath} // ( '/' . ( $finding->{relpath} // '' ) );
        $reprobe = _exposed_reprobe( $home, $rec->{ip}, $rec->{port}, $finding->{domain}, $upath );
    }
    _activity_log( $home, 'exposed_files', 'unblock finding',
        { finding => $finding_id },
        { fn => 'exposed_block',
          args => { job_id => $job_id, finding => $finding_id } } );
    $result->data(
        {
            finding  => $finding_id,
            unblocked => 1,
            reprobed => $reprobe,
        }
    );
    return 1;
}

# ---------------------------------------------------------------------------
# My Activity: one JSON line per change, newest undo one call away.
# ---------------------------------------------------------------------------

our $ACTIVITY_MAX_LINES = 1000;

sub _activity_file {
    my ($home) = @_;
    return "$home/.cpanel/usertools/activity.jsonl";
}

sub _activity_now {
    my @t = gmtime();
    return sprintf( "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0] );
}

sub _activity_log {
    my ( $home, $tool, $action, $summary_hr, $undo_hr ) = @_;
    # Best-effort by design: logging must never break the action that
    # just succeeded, so every failure here is swallowed. One JSON
    # object per line: time, tool, action, summary counts and the undo
    # reference ({fn, args}) when one exists. Callers pass counts and
    # ids only — never file contents, commands, or secrets. The file
    # is capped at $ACTIVITY_MAX_LINES lines (oldest dropped).
    return unless defined $home && $home ne '' && $home ne '/';
    return unless defined $tool && defined $action;
    eval {
        my $dir = "$home/.cpanel/usertools";
        make_path( $dir, { mode => 0700 } );
        my @lines;
        my $file = _activity_file($home);
        if ( open my $fh, '<', $file ) {
            @lines = <$fh>;
            close $fh;
            chomp @lines;
            @lines = grep { $_ ne '' } @lines;
        }
        push @lines,
          JSON::PP->new()->encode(
            {
                time    => _activity_now(),
                tool    => "$tool",
                action  => "$action",
                summary => ref $summary_hr eq 'HASH' ? $summary_hr : {},
                undo    => ref $undo_hr eq 'HASH' ? $undo_hr : undef,
            }
          );
        splice( @lines, 0, @lines - $ACTIVITY_MAX_LINES )
          if @lines > $ACTIVITY_MAX_LINES;
        open my $out, '>', $file or die "cannot write: $!";
        print $out "$_\n" for @lines;
        close $out;
        chmod 0600, $file;
    };
    return;
}

sub _activity_list {
    my ( $home, $limit ) = @_;
    # Newest first, up to $limit entries; unreadable lines are skipped.
    $limit = 100 unless defined $limit && $limit =~ /^\d+$/ && $limit > 0;
    $limit = 100 if $limit > 100;
    my @out;
    my $file = _activity_file($home);
    if ( open my $fh, '<', $file ) {
        my @lines = <$fh>;
        close $fh;
        for my $ln ( reverse @lines ) {
            last if @out >= $limit;
            chomp $ln;
            next if $ln eq '';
            my $rec = eval { JSON::PP->new()->decode($ln) };
            next if $@ || ref $rec ne 'HASH';
            push @out, $rec;
        }
    }
    return \@out;
}

sub _activity_log_job_done {
    my ( $home, $tool, $job_id, $undo_cb, $action ) = @_;
    # Exactly-once completion entry for detached jobs: the status page
    # is polled, so a sidecar flag file marks jobs already recorded.
    # Only jobs with a result summary count as done; cancelled jobs
    # have their own line from the cancel action, and dry runs change
    # nothing. $undo_cb->($summary, $meta) builds the undo reference.
    my $job = _job_paths( $home, $job_id );
    return unless defined $job;
    my $flag = "$job->{dir}/$job_id.activity_logged";
    return if -f $flag;
    my $meta = _read_json_file( $job->{meta} );
    return unless ref $meta eq 'HASH';
    return if $meta->{dry_run};
    my $file = _read_json_file( $job->{result} );
    my $summary = ( $file && ref $file->{counts} eq 'HASH' ) ? $file : undef;
    if ( !defined $summary ) {
        # Deploy-family jobs record ok/result instead of counts.
        $summary = $file if ref $file eq 'HASH' && defined $file->{ok};
    }
    return unless defined $summary;
    return if -f $job->{cancelled};
    my $counts = ref $summary->{counts} eq 'HASH' ? $summary->{counts} : {};
    my %entry = (
        job_id => $job_id,
        kind   => $meta->{tool} // '',
    );
    $entry{changed}     = $counts->{changed} // 0;
    $entry{timed_out}   = $summary->{timed_out} ? 1 : 0;
    $entry{interrupted} = $summary->{interrupted} ? 1 : 0;
    $entry{ok}          = $file->{ok} ? 1 : 0 if defined $file->{ok};
    $entry{trash_batch} = $summary->{trash_batch}
      if defined $summary->{trash_batch};
    my $undo = ref $undo_cb eq 'CODE' ? $undo_cb->( $summary, $meta ) : undef;
    _activity_log( $home, $tool, defined $action ? $action : 'job done',
        \%entry, $undo );
    if ( open my $fh, '>', $flag ) {
        print $fh time(), "\n";
        close $fh;
        chmod 0600, $flag;
    }
    return;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   activity_list - Latest account changes with undo references.
#-------------------------------------------------------------------------------------------------
sub activity_list {
    my ( $args, $result ) = @_;

    return unless _gate_tool( $result, $FEATURE_ACTIVITY );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    $result->data( { entries => _activity_list( $home, 100 ) } );
    return 1;
}

# ---------------------------------------------------------------------------
# Cron Doctor: read-only flags over the user's own crontab, one fix
# (silence a line's output) with full-crontab backup and undo.
# ---------------------------------------------------------------------------

our $CRON_MAX_BYTES = 65536;

sub _cron_policy_enabled {
    my ($result) = @_;
    # Off by default: the WHM policy must explicitly say 1.
    my $policy = _read_user_policy();
    if ( ref $policy eq 'HASH' && ( $policy->{enable_cron_doctor} // '' ) eq '1' ) {
        return 1;
    }
    $result->error('This feature is not enabled for your account.');
    return 0;
}

sub _cron_parse {
    my ( $content, $home, $domains_ar ) = @_;
    # Parse a crontab into per-line records plus findings. Pure function
    # of the text (isolated for tests); file checks run as the caller.
    # Every physical line gets a stable id (L1..Ln); only schedule
    # entries are fixable (silence output). $domains_ar holds the
    # account's own domain names for the wget/curl advice.
    my @lines = defined $content && $content ne ''
      ? split( /(?<=\n)/, $content ) : ();
    my @recs;
    my %seen;
    my $n = 0;
    for my $raw (@lines) {
        $n++;
        ( my $text = $raw ) =~ s/\r?\n\z//;
        my %rec = ( id => "L$n", raw => $text );
        if ( $text =~ /^\s*$/ ) {
            $rec{kind} = 'blank';
        }
        elsif ( $text =~ /^\s*#/ ) {
            $rec{kind} = 'comment';
        }
        elsif ( $text =~ /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/ ) {
            $rec{kind} = 'env';
        }
        else {
            my ( $sched, $cmd );
            if ( $text =~ /^\s*(\@\w+)\s+(.*\S)\s*$/ ) {
                ( $sched, $cmd ) = ( $1, $2 );
            }
            elsif ( $text =~ /^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*\S)\s*$/ ) {
                ( $sched, $cmd ) = ( "$1 $2 $3 $4 $5", $6 );
            }
            if ( !defined $sched ) {
                $rec{kind} = 'other';
            }
            else {
                $rec{kind}     = 'entry';
                $rec{schedule} = $sched;
                $rec{command}  = $cmd;
            }
        }
        if ( ( $rec{kind} // '' ) eq 'entry' ) {
            $seen{ _cron_norm( $rec{schedule} . ' ' . $rec{command} ) }++;
        }
        push @recs, \%rec;
    }
    my @findings;
    for my $rec (@recs) {
        next unless ( $rec->{kind} // '' ) eq 'entry';
        my $flags = _cron_flags( $rec, $home, $domains_ar );
        for my $f ( @{$flags} ) {
            push @findings,
              { line => $rec->{id}, kind => $f->{kind}, text => $f->{text} };
        }
        $rec->{flags} = $flags;
        $rec->{fixable} =
          ( ( $rec->{kind} // '' ) eq 'entry'
              && grep { $_->{kind} eq 'no_redirect' } @{$flags} ) ? 1 : 0;
        if ( $seen{ _cron_norm( $rec->{schedule} . ' ' . $rec->{command} ) } > 1 ) {
            my $dupe = {
                kind => 'duplicate',
                text => 'This line runs the same schedule and command as '
                  . 'another line; one of them is probably left over.',
            };
            push @findings,
              { line => $rec->{id}, kind => 'duplicate', text => $dupe->{text} };
            push @{ $rec->{flags} }, $dupe;
        }
    }
    return { lines => \@recs, findings => \@findings };
}

sub _cron_norm {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/\s+/ /g;
    $s =~ s/^ //;
    $s =~ s/ $//;
    return $s;
}

sub _cron_flags {
    my ( $rec, $home, $domains_ar ) = @_;
    # One advice record per problem on a schedule entry. No state, no
    # writes; file checks use -e as the caller (symlinks followed for
    # the existence question only, nothing is opened).
    my @out;
    my $sched = $rec->{schedule} // '';
    my $cmd   = $rec->{command} // '';
    my ($minute) = split / /, $sched, 2;
    if ( defined $minute && ( $minute eq '*' || $minute eq '*/1' ) ) {
        push @out,
          {
            kind => 'every_minute',
            text => 'Runs every minute. Make sure the job finishes in '
              . 'seconds; overlapping runs pile up and hit account limits.',
          };
    }
    if ( $cmd !~ />/ && $cmd !~ /-O\s+\/dev\/null/ ) {
        push @out,
          {
            kind => 'no_redirect',
            text => 'Output is not redirected, so every run emails the '
              . 'account. Silence it (the fix below) or point it at a log.',
          };
    }
    my @toks = _cron_cmd_tokens($cmd);
    my $first = @toks ? $toks[0] : '';
    ( my $bare = $first ) =~ s/^['"]//;
    $bare =~ s/['"]$//;
    if ( $bare ne '' && $bare !~ m{/} && $bare =~ /^php[\d.]*$/ ) {
        push @out,
          {
            kind => 'bare_php',
            text => 'Calls php without a path; cron does not inherit '
              . 'your shell PATH. Use the full binary path instead.',
          };
    }
    my @missing = _cron_missing_scripts( $cmd, $home );
    if (@missing) {
        push @out,
          {
            kind => 'missing_script',
            text => 'These script files do not exist: '
              . join( ', ', @missing )
              . '. The job fails every run until the path is fixed.',
          };
    }
    if ( _cron_fetches_own_url( $cmd, $domains_ar ) ) {
        push @out,
          {
            kind => 'own_url_fetch',
            text => 'Fetches one of your own URLs over HTTP. Cron does '
              . 'not need a web request: run the script with the PHP '
              . 'binary instead.',
          };
    }
    return \@out;
}

sub _cron_cmd_tokens {
    my ($cmd) = @_;
    # Whitespace tokens with surrounding quotes stripped; redirection
    # targets stay attached to their operator token when joined by
    # whitespace (handled by the caller looking at neighbours).
    my @toks;
    for my $t ( split /[ \t]+/, ( $cmd // '' ) ) {
        next if $t eq '';
        $t =~ s/^['"]//;
        $t =~ s/['"]$//;
        $t =~ s/;$//;
        push @toks, $t if $t ne '';
    }
    return @toks;
}

sub _cron_missing_scripts {
    my ( $cmd, $home ) = @_;
    # Absolute script paths (or home-relative ones) that do not exist.
    # Redirect targets and /dev/null are not scripts.
    my @toks = _cron_cmd_tokens($cmd);
    my @missing;
    for my $i ( 0 .. $#toks ) {
        my $t = $toks[$i];
        next if $t =~ m{://};    # URLs are not files (own-url fetch covers those)
        my $prev = $i > 0 ? $toks[ $i - 1 ] : '';
        next if $prev =~ /^(>>?|<<?|2>>?|&|\|)$/;
        next if $t eq '/dev/null';
        my $abs = undef;
        if ( index( $t, '/' ) == 0 ) {
            $abs = $t;
        }
        elsif ( defined $home && $home ne '' && $t =~ m{/}
            && $t =~ /\.(php|phar|sh|bash|pl|py|rb|js|cgi)$/ )
        {
            $abs = "$home/$t";
        }
        else {
            next;
        }
        if ( $i == 0 || $abs =~ /\.(php|phar|sh|bash|pl|py|rb|js|cgi)$/ ) {
            if ( !-e $abs ) {
                push @missing, $t;
            }
        }
    }
    my %uniq;
    return grep { !$uniq{$_}++ } @missing;
}

sub _cron_fetches_own_url {
    my ( $cmd, $domains_ar ) = @_;
    return 0 unless defined $cmd && $cmd ne '';
    return 0 unless $cmd =~ /(?:^|[\s;|&\/])(?:curl|wget)(?=\s|$)/;
    for my $d ( @{$domains_ar} ) {
        next unless defined $d && $d ne '';
        if ( index( lc($cmd), lc($d) ) >= 0 ) {
            return 1;
        }
    }
    return 0;
}

sub _cron_backup_dir {
    my ($home) = @_;
    return "$home/.cpanel/usertools/cron";
}

sub _cron_backup_write {
    my ( $home, $content ) = @_;
    # Full crontab backup before a fix (0600, newest 3 kept).
    # Returns the basename or undef.
    my $dir = _cron_backup_dir($home);
    eval { make_path( $dir, { mode => 0700 } ) };
    return undef if $@;
    my $name = 'crontab-' . _journal_timestamp() . '.bak';
    my $path = "$dir/$name";
    open my $fh, '>', $path or return undef;
    print $fh $content;
    close $fh;
    chmod 0600, $path;
    if ( opendir( my $dh, $dir ) ) {
        my @all = sort grep { /^crontab-.*\.bak$/ } readdir $dh;
        closedir $dh;
        while ( @all > 3 ) {
            my $old = shift @all;
            next if $old eq $name;
            unlink "$dir/$old";
        }
    }
    return $name;
}

sub _cron_backup_latest {
    my ($home) = @_;
    my $dir = _cron_backup_dir($home);
    return undef unless opendir( my $dh, $dir );
    my @all = sort grep { /^crontab-.*\.bak$/ } readdir $dh;
    closedir $dh;
    return @all ? "$dir/$all[-1]" : undef;
}

sub _cron_find_line {
    my ( $lines_ar, $line_id ) = @_;
    # The id names a physical line (L1..Ln); the caller also supplies
    # the text it displayed, and the fix refuses when the live line
    # differs (the crontab changed under the scan, e.g. wrapper-added
    # environment lines shifting everything down).
    return undef unless defined $line_id && $line_id =~ /^L(\d+)$/;
    my $idx = $1 - 1;
    return undef if $idx < 0 || $idx > $#{$lines_ar};
    my $rec = $lines_ar->[$idx];
    return undef unless ref $rec eq 'HASH' && $rec->{id} eq $line_id;
    return $rec;
}

sub _cron_silenced {
    my ($command) = @_;
    return $command . ' >/dev/null 2>&1';
}

sub _cron_gate {
    my ( $result, $user_r ) = @_;
    return 0 unless _gate_tool( $result, $FEATURE_CRON_DOCTOR );
    return 0 unless _cron_policy_enabled($result);
    my ( $user, $uid, $home ) = _gate_caller($result);
    return 0 unless defined $user;
    $$user_r = { user => $user, uid => $uid, home => $home };
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   cron_scan - Flag risky cron lines (read-only).
#-------------------------------------------------------------------------------------------------
sub cron_scan {
    my ( $args, $result ) = @_;

    my $ctx;
    return unless _cron_gate( $result, \$ctx );
    my ( $content, $err ) = _cron_read();
    if ( !defined $content ) {
        $result->error( 'Cannot read crontab: [_1].', $err );
        return;
    }
    my @domains = map { $_->{domain} } _user_domains( $ctx->{user} );
    my $parsed = _cron_parse( $content, $ctx->{home}, \@domains );
    $result->data(
        {
            present  => $content ne '' ? 1 : 0,
            lines    => $parsed->{lines},
            findings => $parsed->{findings},
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   cron_fix_preview - Show the silenced line before writing it.
#-------------------------------------------------------------------------------------------------
sub cron_fix_preview {
    my ( $args, $result ) = @_;

    my $ctx;
    return unless _cron_gate( $result, \$ctx );
    my ($line_id) = $args->get('line');
    my ($text)   = $args->get('text');
    my ( $plan, $err ) = _cron_fix_plan( $ctx, $line_id, $text );
    if ( !defined $plan ) {
        $result->error( 'Nothing to fix: [_1].', $err );
        return;
    }
    $result->data($plan);
    return 1;
}

sub _cron_fix_plan {
    my ( $ctx, $line_id, $text ) = @_;
    # The line must still read exactly as scanned; only unredirected
    # schedule entries qualify.
    my ( $content, $err ) = _cron_read();
    if ( !defined $content ) {
        return ( undef, "cannot read crontab: $err" );
    }
    my @domains = map { $_->{domain} } _user_domains( $ctx->{user} );
    my $parsed = _cron_parse( $content, $ctx->{home}, \@domains );
    my $rec = _cron_find_line( $parsed->{lines}, $line_id );
    if ( !defined $rec ) {
        return ( undef, 'unknown line' );
    }
    if ( ( $rec->{kind} // '' ) ne 'entry' ) {
        return ( undef, 'only schedule entries can be silenced' );
    }
    if ( defined $text && $text ne '' && $text ne $rec->{raw} ) {
        return ( undef, 'the crontab changed since the scan' );
    }
    if ( $rec->{command} =~ />/ ) {
        return ( undef, 'output is already redirected' );
    }
    if ( length($content) + length(' >/dev/null 2>&1') > $CRON_MAX_BYTES ) {
        return ( undef, 'crontab is too large' );
    }
    my $old = $rec->{raw};
    my $new = $rec->{schedule} . ' ' . _cron_silenced( $rec->{command} );
    return ( { line => $rec->{id}, old => $old, new => $new }, undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   cron_fix_output - Silence one line's output (backup kept, undo ready).
#-------------------------------------------------------------------------------------------------
sub cron_fix_output {
    my ( $args, $result ) = @_;

    my $ctx;
    return unless _cron_gate( $result, \$ctx );
    my ($line_id) = $args->get('line');
    my ($text)   = $args->get('text');
    my ( $plan, $err ) = _cron_fix_plan( $ctx, $line_id, $text );
    if ( !defined $plan ) {
        $result->error( 'Nothing to fix: [_1].', $err );
        return;
    }
    my ( $content, $read_err ) = _cron_read();
    if ( !defined $content ) {
        $result->error( 'Cannot read crontab: [_1].', $read_err );
        return;
    }
    my $backup = _cron_backup_write( $ctx->{home}, $content );
    if ( !defined $backup ) {
        $result->error('Could not back up the crontab; nothing was changed.');
        return;
    }
    my @lines = split /(?<=\n)/, $content;
    $lines[ $1 - 1 ] = $plan->{new} . "\n"
      if $line_id =~ /^L(\d+)$/ && $1 - 1 <= $#lines;
    my $new_content = join '', @lines;
    if ( my $werr = _cron_write($new_content) ) {
        $result->error( 'Could not write crontab: [_1].', $werr );
        return;
    }
    _activity_log(
        $ctx->{home}, 'cron_doctor', 'silence cron line',
        { line => $line_id },
        { fn => 'cron_undo', args => {} }
    );
    $result->data(
        { line => $line_id, old => $plan->{old}, new => $plan->{new}, backup => $backup } );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   cron_undo - Restore the newest backed-up crontab.
#-------------------------------------------------------------------------------------------------
sub cron_undo {
    my ( $args, $result ) = @_;

    my $ctx;
    return unless _cron_gate( $result, \$ctx );
    my $latest = _cron_backup_latest( $ctx->{home} );
    if ( !defined $latest ) {
        $result->error('No backup found: nothing to undo.');
        return;
    }
    my $fh;
    if ( !open $fh, '<', $latest ) {
        $result->error('Could not read the backup.');
        return;
    }
    local $/;
    my $content = <$fh>;
    close $fh;
    if ( my $werr = _cron_write( $content // '' ) ) {
        $result->error( 'Could not write crontab: [_1].', $werr );
        return;
    }
    unlink $latest;
    _activity_log( $ctx->{home}, 'cron_doctor', 'undo cron fix',
        { backup => ( split m{/}, $latest )[-1] }, undef );
    $result->data( { restored => 1 } );
    return 1;
}

# ---------------------------------------------------------------------------
# App Helper (tool E): Laravel maintenance that runs purely as
# the user. No docroot changes and no privileged code in this step.
# ---------------------------------------------------------------------------

use HTTP::Tiny ();

our $ARTISAN_TIMEOUT = 120;
our $ARTISAN_OUTPUT_CAP = 65536;
our $ENV_CHECK_MAX_BYTES = 4096;
our $ENV_CHECK_TIMEOUT = 5;
our $MAX_ADDED_APPS = 20;

our %ARTISAN_COMMANDS = map { $_ => 1 } qw(
  optimize:clear optimize cache:clear config:clear config:cache
  route:clear route:cache view:clear view:cache storage:link
);

sub _apps_file {
    my ($home) = @_;
    return "$home/.cpanel/usertools/apps.json";
}

sub _read_added_apps {
    my ($home) = @_;
    my $file = _apps_file($home);
    open my $fh, '<', $file or return [];
    local $/;
    my $raw = <$fh>;
    close $fh;
    my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
    if ( $@ || ref $data ne 'HASH' || ref $data->{apps} ne 'ARRAY' ) {
        return [];
    }
    my @paths;
    for my $e ( @{ $data->{apps} } ) {
        push @paths, $e->{path} if ref $e eq 'HASH' && defined $e->{path};
    }
    return \@paths;
}

sub _write_added_apps {
    my ( $home, $paths_ar ) = @_;
    my $dir = "$home/.cpanel/usertools";
    eval { make_path( $dir, { mode => 0700 } ) };
    return 0 if $@;
    my @entries = map { { path => $_, added => time() } } @{$paths_ar};
    my $tmp = _apps_file($home) . ".tmp.$$";
    my $fh;
    if ( !open $fh, '>', $tmp ) {
        return 0;
    }
    print $fh JSON::PP->new()->canonical(1)->encode( { apps => \@entries } );
    close $fh;
    chmod 0600, $tmp;
    return rename( $tmp, _apps_file($home) ) ? 1 : 0;
}

sub _scan_detected_apps {
    my ($home) = @_;
    # Synchronous engine scan (read-only, depth-bounded). Returns app records
    # ({path, framework_version}). Dies on spawn failure; callers turn that
    # into an error.
    my $py  = $TEST_ENGINE_BIN // $ENGINE_PYTHON;
    my $bin = $TEST_ENGINE     // $ENGINE_PATH;
    my @cmd = ( $py, $bin, 'scan-apps', '--scope', $home );
    if ( ( $ENV{USERTOOLS_TESTING} // '' ) eq '1' && defined $TEST_HOME ) {
        push @cmd, '--home', $home;
    }
    open my $fh, '-|', @cmd or die "cannot run scan-apps: $!";
    local $/;
    my $out = <$fh>;
    close $fh;
    my $data = eval { JSON::PP->new()->decode( $out // '' ) };
    if ( $@ || ref $data ne 'HASH' || ref $data->{paths}{apps} ne 'ARRAY' ) {
        die "scan-apps returned an unreadable summary";
    }
    return $data->{paths}{apps};
}

sub _docroot_mapped {
    my ( $docroot, $approot ) = @_;
    # Boundary-safe both directions: equal, app under docroot, or docroot
    # under app root. Used by the .env check and PHP default selection.
    return 0 unless defined $docroot && $docroot ne '';
    return 1 if $docroot eq $approot;
    return 1 if index( $approot, "$docroot/" ) == 0;
    return 1 if index( $docroot, "$approot/" ) == 0;
    return 0;
}

sub _normalize_rel {
    my ($path) = @_;
    return undef unless defined $path && $path ne '' && $path !~ m{^/};
    my @parts = grep { $_ ne '' && $_ ne '.' } split m{/}, $path;
    return undef unless @parts && !grep { $_ eq '..' } @parts;
    return join( '/', @parts );
}

sub _validate_app_path {
    my ( $home, $path ) = @_;
    # Structural rules only (mirrors scope validation): home-relative, real,
    # a directory, not a symlink itself, not protected.
    my $rel = _normalize_rel($path);
    if ( !defined $rel ) {
        return ( undef, 'app must be a home-relative path' );
    }
    my $abs = "$home/$rel";
    my @st = lstat $abs;
    if ( !@st ) {
        return ( undef, 'app directory does not exist' );
    }
    if ( -l _ ) {
        return ( undef, 'app must not be a symlink' );
    }
    if ( !-d _ ) {
        return ( undef, 'app must be a directory' );
    }
    my $real = realpath($abs);
    if ( !defined $real || ( $real ne $home && index( $real, "$home/" ) != 0 ) ) {
        return ( undef, 'app is outside your home directory' );
    }
    my $hrel = $real eq $home ? '.' : substr( $real, length("$home/") );
    my ($first) = split m{/}, $hrel;
    if ( $first ne '.' && ( $first =~ /^\./ || grep { $_ eq $first } qw(etc mail ssl tmp logs access-logs) ) ) {
        return ( undef, 'app is inside a protected path' );
    }
    return ( $rel, undef );
}

sub _resolve_app {
    my ( $home, $path ) = @_;
    # Full validation on every call: structural rules plus membership in the
    # freshly detected list or the manually added list.
    my ( $rel, $err ) = _validate_app_path( $home, $path );
    if ( !defined $rel ) {
        return ( undef, $err );
    }
    my %known;
    my $detected = eval { _scan_detected_apps($home) };
    if ($@) {
        return ( undef, 'app scan failed; try again' );
    }
    $known{ $_->{path} } = 1 for @{$detected};
    $known{$_} = 1 for @{ _read_added_apps($home) };
    if ( !$known{$rel} ) {
        return ( undef, 'app is not in the detected or added list' );
    }
    return ( "$home/$rel", undef );
}

sub _domain_kind_of {
    my ($rec) = @_;
    # Best-effort classification from whatever type fields DomainInfo
    # carries.
    for my $k (qw(domain_type type kind)) {
        my $t = $rec->{$k};
        next unless defined $t && !ref $t;
        return 'addon'  if $t =~ /addon/i;
        return 'sub'    if $t =~ /^\s*sub/i;
        return 'parked' if $t =~ /park|alias/i;
        return 'main'   if $t =~ /main|primary/i;
    }
    return undef;
}

sub _parse_domaininfo {
    my ($data) = @_;
    # Parse of DomainInfo domains_data on cPanel 11.138:
    # result.data = { main_domain => {HASH}, addon_domains => [..],
    # parked_domains => [..], sub_domains => [..] } where each record
    # (main_domain included) is a hash with customlog, documentroot, domain,
    # group, hascgi, homedir, ip, is_temporary, owner,
    # phpopenbasedirprotect, port, scriptalias, serveradmin, serveralias,
    # servername, status, type, usecanonicalname, user. Scalar main_domain
    # and flat {data:[...]} are kept only as fallbacks.
    # Returns (\@records, $main_or_undef); records carry
    # {domain, documentroot, kind}.
    my @recs;
    my $main_domain;
    my $d = ref $data eq 'HASH'
      ? ( ( ref $data->{result} eq 'HASH' && defined $data->{result}{data} )
          ? $data->{result}{data}
          : $data->{data} )
      : undef;
    if ( ref $d eq 'ARRAY' ) {
        for my $r ( @{$d} ) {
            next unless ref $r eq 'HASH';
            next unless defined $r->{domain} && defined $r->{documentroot};
            push @recs, { domain => $r->{domain}, documentroot => $r->{documentroot}, kind => _domain_kind_of($r) };
        }
        if ( ref $data->{main_domain} eq 'HASH' && defined $data->{main_domain}{domain} && !ref $data->{main_domain}{domain} ) {
            $main_domain = $data->{main_domain}{domain};
        }
        elsif ( defined $data->{main_domain} && !ref $data->{main_domain} ) {
            $main_domain = $data->{main_domain};
        }
    }
    elsif ( ref $d eq 'HASH' ) {
        if ( ref $d->{main_domain} eq 'HASH' ) {
            my $mr = $d->{main_domain};
            if ( defined $mr->{domain} && !ref $mr->{domain} ) {
                $main_domain = $mr->{domain};
                if ( defined $mr->{documentroot} && !ref $mr->{documentroot} ) {
                    push @recs,
                      { domain => $mr->{domain}, documentroot => $mr->{documentroot}, kind => 'main' };
                }
            }
        }
        elsif ( defined $d->{main_domain} && !ref $d->{main_domain} ) {
            $main_domain = $d->{main_domain};
        }
        my %kind_of = (
            addon_domains => 'addon', sub_domains => 'sub',
            parked_domains => 'parked', alias_domains => 'parked',
        );
        for my $key ( sort keys %{$d} ) {
            my $list = $d->{$key};
            next unless ref $list eq 'ARRAY';
            my $forced = $kind_of{$key};
            for my $r ( @{$list} ) {
                next unless ref $r eq 'HASH';
                next unless defined $r->{domain} && defined $r->{documentroot};
                next if defined $main_domain && lc( $r->{domain} ) eq lc($main_domain) && grep { lc( $_->{domain} ) eq lc($main_domain) } @recs;
                push @recs,
                  { domain => $r->{domain}, documentroot => $r->{documentroot},
                    kind => defined $forced ? $forced : _domain_kind_of($r) };
            }
        }
    }
    return ( \@recs, $main_domain );
}

sub _userdata_main_domain {
    my ($user) = @_;
    # The userdata 'main' file names the primary domain (best effort).
    my $base = defined $TEST_DOMAIN_DATA_DIR ? $TEST_DOMAIN_DATA_DIR : '/var/cpanel/userdata';
    my $file = "$base/$user/main";
    if ( open my $fh, '<', $file ) {
        while ( my $line = <$fh> ) {
            if ( $line =~ /^\s*(?:main_domain|domain|servername):\s*(\S+)\s*$/ ) {
                close $fh;
                return $1;
            }
        }
        close $fh;
    }
    return undef;
}

sub _call_uapi {
    my ( $mod, $fn ) = @_;
    # In-process UAPI as the caller (this code already runs as the user, so
    # no username travels anywhere). The `uapi --user=` CLI is NOT used
    # here: setuid-as-user from a user process dies on the server ("setuids
    # failed") and silently degrades everything to fallbacks. Root-context
    # callers (Admin modules, hook file reads) keep the CLI, where --user is
    # valid. Returns the decoded envelope hash or undef. Accepts blessed
    # Cpanel::Result (methods) and plain test hashes; API-level failure
    # (status != 1) degrades to the fallback instead of parsing garbage.
    my $res = eval { Cpanel::API::execute( $mod, $fn, {} ) };
    if ( $@ || !defined $res || !ref $res ) {
        return undef;
    }
    my ( $st, undef ) = _uapi_result_status($res);
    if ( !defined $st || $st != 1 ) {
        return undef;
    }
    if ( eval { $res->can('data') } ) {
        my $d = eval { $res->data() };
        if ( ref $d eq 'HASH' || ref $d eq 'ARRAY' ) {
            return { data => $d };
        }
        return undef;
    }
    if ( ref $res eq 'HASH' ) {
        return $res;
    }
    return undef;
}

sub _user_domain_info {
    my ($user) = @_;
    # Rich enumeration for docroot/htaccess work: (\@records, $main_domain).
    # Same two server-side sources as _user_domains (never request data).
    my $data = _call_uapi( 'DomainInfo', 'domains_data' );
    if ( ref $data eq 'HASH' ) {
        my ( $recs, $main_domain ) = _parse_domaininfo($data);
        if ( @{$recs} ) {
            if ( !defined $main_domain ) {
                $main_domain = _userdata_main_domain($user);
            }
            return ( $recs, $main_domain );
        }
        if ( defined $main_domain ) {
            my @fb = _user_domains_userdata($user);
            for my $r (@fb) {
                $r->{kind} = undef unless exists $r->{kind};
            }
            if (@fb) {
                return ( \@fb, $main_domain );
            }
            return ( [], $main_domain );
        }
    }
    my @recs = _user_domains_userdata($user);
    for my $r (@recs) {
        $r->{kind} = undef unless exists $r->{kind};
    }
    return ( \@recs, _userdata_main_domain($user) );
}

sub _user_domains {
    my ($user) = @_;
    # DOMAINS COME ONLY FROM HERE (never from request parameters — that would
    # let a caller aim the .env check at arbitrary hosts). Primary: in-process
    # UAPI DomainInfo as the caller; fallback: the server's userdata records.
    # Both are best-effort; failure means an empty list, and the .env check
    # then reports it cannot list domains.
    # Returns a list of { domain, documentroot }.
    my ($recs) = _user_domain_info($user);
    return map { { domain => $_->{domain}, documentroot => $_->{documentroot} } } @{$recs};
}

sub _user_domains_userdata {
    my ($user) = @_;
    my $base = defined $TEST_DOMAIN_DATA_DIR ? $TEST_DOMAIN_DATA_DIR : '/var/cpanel/userdata';
    my $dir = "$base/$user";
    my $dh;
    if ( !opendir( $dh, $dir ) ) {
        return ();
    }
    my @files = grep { -f "$dir/$_" } readdir $dh;
    closedir $dh;
    my @domains;
    for my $f ( sort @files ) {
        # cPanel's internal vhost files are not domains: skip the control
        # files (main, cache), cache/SSL sidecars (_SSL, .cache), structured
        # records (.json, .yaml, .php-fpm.*) and anything that is not shaped
        # like a domain name (unfiltered, the guard once probed
        # https://<domain>_SSL/.env).
        next if $f eq 'main' || $f eq 'cache' || $f =~ /^\./;
        next if $f =~ /(?:_SSL|\.cache|\.json|\.yaml)$/ || $f =~ /\.php-fpm\./;
        next unless $f =~ /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
        open my $fh, '<', "$dir/$f" or next;
        my $docroot;
        while ( my $line = <$fh> ) {
            if ( $line =~ /^\s*documentroot:\s*(\S+)\s*$/ ) {
                $docroot = $1;
                last;
            }
        }
        close $fh;
        if ( defined $docroot ) {
            push @domains, { domain => $f, documentroot => $docroot };
        }
    }
    return @domains;
}

sub _mapped_domains {
    my ( $user, $approot, $all_ar ) = @_;
    # Sorted domains mapped to the app (equal docroot or either side
    # containing, boundary-safe). Server-side data only; $all_ar optionally
    # supplies a pre-fetched domain list to avoid a second enumeration.
    my @all = defined $all_ar ? @{$all_ar} : _user_domains($user);
    my @mapped = grep { _docroot_mapped( $_->{documentroot}, $approot ) } @all;
    my @sorted = sort { $a->{domain} cmp $b->{domain} } @mapped;
    return @sorted;
}

sub _app_domain_names {
    my ( $user, $approot, $all_ar ) = @_;
    # Names only, deduplicated and sorted, for app_helper_list rows.
    # Client-side flattening cannot do this: docroots are absolute while
    # app paths are home-relative, so the page's old match always failed.
    my %seen;
    return [ grep { !$seen{$_}++ } map { $_->{domain} } _mapped_domains( $user, $approot, $all_ar ) ];
}

sub _fetch_langphp_data {
    my ($user) = @_;
    # Decoded LangPHP vhost-versions envelope, or undef. Shared by the
    # mapped-domain and account-wide lookups so shape handling lives in
    # one place.
    return _call_uapi( 'LangPHP', 'php_get_vhost_versions' );
}

sub _collect_vhost_versions {
    my ( $node, $map_hr ) = @_;
    # Tolerant per-vhost parse: every record carrying a domain-like field
    # (domain/vhost/servername) plus a version-like field
    # (php_version/version/php) contributes lc(host) => 'NN'. Unknown shapes
    # contribute nothing and the callers fall back gracefully.
    if ( ref $node eq 'HASH' ) {
        my ($dkey) = grep { /^(?:domain|vhost|servername)$/i } keys %{$node};
        my ($vkey) = grep { /^(?:php_version|version|php)$/i } keys %{$node};
        if ( defined $dkey && defined $vkey && !ref $node->{$dkey} && !ref $node->{$vkey} ) {
            # Capture at once: a later match would clobber $1.
            my ($ver)  = $node->{$vkey} =~ /ea-php(\d\d)/;
            my ($host) = $node->{$dkey} =~ /(\S+)/;
            if ( defined $ver && defined $host ) {
                $map_hr->{ lc($host) } = $ver;
            }
        }
        for my $v ( values %{$node} ) {
            _collect_vhost_versions( $v, $map_hr ) if ref $v;
        }
    }
    elsif ( ref $node eq 'ARRAY' ) {
        for my $v ( @{$node} ) {
            _collect_vhost_versions( $v, $map_hr ) if ref $v;
        }
    }
    return;
}

sub _mapped_domain_php_version {
    my ( $user, $approot ) = @_;
    # Prefer the version of the app's MAPPED domain (per-vhost records),
    # not just any single version on the account. Falls back to the
    # account-wide single-distinct version, then undef (newest installed).
    my @mapped = _mapped_domains( $user, $approot );
    if (@mapped) {
        my $data = _fetch_langphp_data($user);
        if ( ref $data eq 'HASH' ) {
            my %map;
            _collect_vhost_versions( $data, \%map );
            my %seen;
            for my $m (@mapped) {
                my $v = $map{ lc( $m->{domain} // '' ) };
                $seen{$v} = 1 if defined $v;
            }
            my @vers = sort keys %seen;
            if ( @vers == 1 && $vers[0] =~ /^\d\d$/ ) {
                return $vers[0];
            }
            my $ver = _account_php_version($data);
            if ( defined $ver ) {
                return $ver;
            }
        }
    }
    return undef;
}

sub _collect_strings {
    my ( $node, $out_ar ) = @_;
    if ( !ref $node ) {
        push @{$out_ar}, "$node" if defined $node;
        return;
    }
    if ( ref $node eq 'HASH' ) {
        _collect_strings( $_, $out_ar ) for values %{$node};
        return;
    }
    if ( ref $node eq 'ARRAY' ) {
        _collect_strings( $_, $out_ar ) for @{$node};
    }
    return;
}

sub _account_php_version {
    my ($data) = @_;
    # Account-wide single distinct ea-php version, or undef when empty,
    # unparseable or multi-version (unattributable).
    my @strings;
    _collect_strings( $data, \@strings );
    my %seen;
    for my $s (@strings) {
        while ( $s =~ /ea-php(\d+)/g ) {
            $seen{$1} = 1;
        }
    }
    my @found = sort keys %seen;
    if ( @found == 1 && $found[0] =~ /^\d\d$/ ) {
        return $found[0];
    }
    return undef;
}

sub _select_php_for_app {
    my ( $user, $approot ) = @_;
    # Resolution order: the mapped domain's ea-php (MultiPHP), then
    # CloudLinux alt-php, then the account default (newest ea-php, then
    # /usr/local/bin/php). Returns (bin, undef, source). Client-supplied
    # versions keep going through _select_php_bin's allowlist.
    my $ver = _mapped_domain_php_version( $user, $approot );
    if ( defined $ver ) {
        my ( $bin, $err ) = _select_php_bin("ea-php$ver");
        if ( defined $bin ) {
            return ( $bin, undef, 'mapped' );
        }
    }
    {
        my ( $bin, $err ) = _select_alt_php_bin();
        if ( defined $bin ) {
            return ( $bin, undef, 'alt-php' );
        }
    }
    my ( $bin, $err ) = _select_php_bin(undef);
    if ( defined $bin ) {
        return ( $bin, undef, 'default' );
    }
    return ( undef, $err, undef );
}

sub _select_php_bin {
    my ($version) = @_;
    # Returns an absolute, existing, executable PHP binary or (undef, reason).
    # $version is 'ea-phpXY' (from LangPHP client-side) or undef (default).
    my $opt = defined $TEST_PHP_DIR ? $TEST_PHP_DIR : '/opt/cpanel';
    if ( defined $version && $version ne '' ) {
        if ( $version !~ /^ea-php(\d\d)$/ ) {
            return ( undef, 'unknown PHP version' );
        }
        my $bin = "$opt/ea-php$1/root/usr/bin/php";
        if ( -f $bin && -x $bin ) {
            return $bin;
        }
        return ( undef, 'PHP binary is not available' );
    }
    if ( opendir( my $dh, $opt ) ) {
        my @vers = sort { $b cmp $a } grep { /^ea-php\d\d$/ } readdir $dh;
        closedir $dh;
        for my $v (@vers) {
            my $bin = "$opt/$v/root/usr/bin/php";
            if ( -f $bin && -x $bin ) {
                return $bin;
            }
        }
    }
    if ( -f '/usr/local/bin/php' && -x '/usr/local/bin/php' ) {
        return '/usr/local/bin/php';
    }
    return ( undef, 'no PHP binary available' );
}

sub _php_bin_allowed {
    my ($bin) = @_;
    # Allowlist for every PHP/Node path before exec: the two vendor
    # trees plus the system PHP. Test seams are honoured only when defined
    # (never in production).
    return 0 unless defined $bin && $bin =~ m{^/} && $bin !~ m{\.\.};
    if ( $bin =~ m{^/opt/cpanel/ea-php\d\d/root/usr/bin/php$} ) {
        return 1;
    }
    if ( $bin =~ m{^/opt/alt/php\d\d/usr/bin/php$} ) {
        return 1;
    }
    if ( $bin eq '/usr/local/bin/php' ) {
        return 1;
    }
    if ( defined $TEST_PHP_DIR && index( $bin, "$TEST_PHP_DIR/" ) == 0 ) {
        return 1;
    }
    if ( defined $TEST_ALT_PHP_DIR && index( $bin, "$TEST_ALT_PHP_DIR/" ) == 0 ) {
        return 1;
    }
    return 0;
}

sub _select_alt_php_bin {
    my () = @_;
    # CloudLinux PHP Selector tier: newest installed alt-php. The exact
    # per-user selector lookup (selectorctl) is not used; the newest
    # installed tree is the documented-safe default. Never required: empty
    # when CloudLinux is absent. Returns (bin, undef) or (undef, reason).
    my $base = defined $TEST_ALT_PHP_DIR ? $TEST_ALT_PHP_DIR : '/opt/alt';
    if ( opendir( my $dh, $base ) ) {
        my @vers = sort { $b cmp $a } grep { /^php\d\d$/ } readdir $dh;
        closedir $dh;
        for my $v (@vers) {
            my $bin = "$base/$v/usr/bin/php";
            if ( -f $bin && -x $bin && _php_bin_allowed($bin) ) {
                return ( $bin, undef );
            }
        }
    }
    return ( undef, 'no alt-php available' );
}

sub _select_nodejs_bin {
    my ( $cpanel_base, $alt_base ) = @_;
    # Node.js for the future build step: cPanel
    # ea-nodejs first, then the CloudLinux Node.js Selector tree, newest of
    # each. Allowlisted before exec. Returns (bin, source) or (undef, reason).
    $cpanel_base = '/opt/cpanel' unless defined $cpanel_base;
    $alt_base    = '/opt/alt' unless defined $alt_base;
    my @families = (
        [ $cpanel_base, qr/^ea-nodejs(\d+)$/, 'bin/node', 'ea-nodejs' ],
        # CloudLinux Node.js lives at /opt/alt/alt-nodejsNN/root/usr/bin
        # (npm is root/usr/bin/npm, a symlink to npm-cli.js), not bin/node.
        [ $alt_base,    qr/^alt-nodejs(\d+)$/, 'root/usr/bin/node', 'alt-nodejs' ],
    );
    for my $fam (@families) {
        my ( $base, $re, $rel, $source ) = @{$fam};
        my $dh;
        if ( !opendir( $dh, $base ) ) {
            next;
        }
        my @cands = map { /$re/ ? [ $1, $_ ] : () } readdir $dh;
        closedir $dh;
        for my $c ( sort { $b->[0] <=> $a->[0] } @cands ) {
            my $bin = "$base/$c->[1]/$rel";
            if ( -f $bin && -x $bin ) {
                return ( $bin, $source );
            }
        }
    }
    return ( undef, 'no Node.js available' );
}

sub _spawn_sync {
    my ( $cmd_ar, $cwd, $env_hr, $timeout, $cap ) = @_;
    # Run @$cmd_ar (argv list, no shell) with cwd + optional env allowlist,
    # in its own session for process-group kill. Returns
    # { exit, output, truncated, timed_out }.
    my ( $rd, $wr );
    if ( !pipe( $rd, $wr ) ) {
        return { exit => -1, output => '', truncated => 0, timed_out => 0, error => "cannot create pipe: $!" };
    }
    my $kid = fork();
    if ( !defined $kid ) {
        close $rd;
        close $wr;
        return { exit => -1, output => '', truncated => 0, timed_out => 0, error => "cannot fork: $!" };
    }
    if ( $kid == 0 ) {
        close $rd;
        setsid();
        if ( !chdir $cwd ) {
            POSIX::_exit(127);
        }
        if ( defined $env_hr ) {
            # Double-forked child past setsid(): replacing the whole
            # environment with the allowlist is deliberate (no caller left
            # for local() to restore to; the child execs or exits).
            ## no critic (Variables::RequireLocalizedPunctuationVars)
            %ENV = %{$env_hr};
        }
        open STDIN, '<', '/dev/null' or POSIX::_exit(127);
        if ( !open STDOUT, '>&', $wr ) {
            POSIX::_exit(127);
        }
        if ( !open STDERR, '>&', $wr ) {
            POSIX::_exit(127);
        }
        close $wr;
        exec { $cmd_ar->[0] } @{$cmd_ar} or POSIX::_exit(127);
    }
    close $wr;
    my $buf = '';
    my $timed_out = 0;
    my $start = time();
    my $deadline = $start + $timeout;
    my $exit = -1;
    my $sig  = 0;
    my $reaped = 0;
    while ( !$reaped ) {
        my $now = time();
        if ( $now >= $deadline ) {
            $timed_out = 1;
            kill( 'KILL', -$kid );
        }
        my $got = waitpid( $kid, WNOHANG );
        if ( $got == $kid ) {
            $exit   = $? >> 8;
            $sig    = $? & 127;
            $reaped = 1;
            last;
        }
        my $rin = '';
        vec( $rin, fileno($rd), 1 ) = 1;
        my $nfound = select( $rin, undef, undef, 0.2 );
        if ( $nfound && $nfound > 0 ) {
            my $chunk;
            my $n = sysread( $rd, $chunk, 65536 );
            if ( !defined $n || $n == 0 ) {
                $reaped = waitpid( $kid, 0 ) == $kid ? 1 : $reaped;
                if ($reaped) {
                    $exit = $? >> 8;
                    $sig  = $? & 127;
                    last;
                }
                next if !$timed_out;
                last;
            }
            $buf .= $chunk;
        }
    }
    close $rd;
    # Reap for certain (harmless if already reaped).
    if ( waitpid( $kid, WNOHANG ) == $kid ) {
        $exit = $? >> 8;
        $sig  = $? & 127;
    }
    my $truncated = 0;
    if ( length($buf) > $cap ) {
        $buf = substr( $buf, 0, $cap );
        $truncated = 1;
    }
    return { exit => $exit, signaled => $sig ? 1 : 0, output => _strip_ansi($buf), truncated => $truncated, timed_out => $timed_out ? 1 : 0 };
}

sub _lve_hint {
    my ($run_hr) = @_;
    # CloudLinux LVE triage: composer/npm/artisan under CPU, memory,
    # IO or process limits die in recognizable ways. Returns plain-language
    # guidance or undef when nothing matches (never raises limits).
    my $out = ref $run_hr eq 'HASH' ? ( $run_hr->{output} // '' ) : '';
    my $exit = ref $run_hr eq 'HASH' ? ( $run_hr->{exit} ) : undef;
    # Exit 137 (128+SIGKILL) is the OOM-killer/LVE kill signature.
    # Treat it as a memory-limit kill even with no output text.
    if ( defined $exit && ( $exit == 137 || $exit == -9 ) ) {
        return 'The task ran out of memory. On CloudLinux hosting this is often '
          . "the plan's resource limit (LVE). Try again, or build locally and upload.";
    }
    if ( ref $run_hr eq 'HASH' && $run_hr->{signaled} ) {
        return 'The task was stopped by the system. On CloudLinux hosting this is often '
          . "the plan's resource limit (LVE). Try again, or build locally and upload.";
    }
    if ( $out =~ /cannot allocate memory|memory exhausted|allowed memory size|out of memory/i ) {
        return 'The task ran out of memory. On CloudLinux hosting this is often '
          . "the plan's resource limit (LVE). Try again, or build locally and upload.";
    }
    if ( $out =~ /resource temporarily unavailable|EAGAIN|fork[^a-z]*fail|too many (processes|open files)/i ) {
        return 'The task hit a process or file limit. On CloudLinux hosting this is often '
          . "the plan's resource limit (LVE). Try again later, or build locally and upload.";
    }
    return undef;
}

sub _deploy_lve_hint {
    # An npm/composer step killed by an LVE limit (exit 137/SIGKILL or
    # a memory fault in the log) reports plain words, never a raw exit code.
    my ( $final, $log ) = @_;
    $log = '' unless defined $log;
    if ( $log =~ /cannot allocate memory|memory exhausted|allowed memory size|out of memory|\bKilled\b/i ) {
        return 'Your account hit its memory limit while building; ask your host or build locally';
    }
    if ( ref $final eq 'HASH' && ref $final->{steps} eq 'ARRAY' ) {
        for my $s ( @{ $final->{steps} } ) {
            next unless ref $s eq 'HASH';
            my $exit = $s->{exit};
            if ( defined $exit && ( $exit == 137 || $exit == -9 ) ) {
                return 'Your account hit its memory limit while building; ask your host or build locally';
            }
            if ( defined $s->{error} && $s->{error} =~ /cannot allocate memory|out of memory/i ) {
                return 'Your account hit its memory limit while building; ask your host or build locally';
            }
        }
    }
    return undef;
}

sub _artisan_lock_path {
    my ( $home, $rel ) = @_;
    my $safe = $rel;
    $safe =~ s{[^A-Za-z0-9_-]}{_}g;
    $safe = substr( $safe, 0, 100 );
    return "$home/.cpanel/usertools/artisan-$safe.lock";
}

sub _read_dotenv_key {
    my ( $approot, $key ) = @_;
    my $file = "$approot/.env";
    open my $fh, '<', $file or return undef;
    while ( my $line = <$fh> ) {
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^#/;
        if ( $line =~ /^\Q$key\E\s*=\s*(.*)$/ ) {
            close $fh;
            my $val = $1;
            $val =~ s/^\s+|\s+$//g;
            $val =~ s/^(['"])(.*)\1$/$2/;
            return $val;
        }
    }
    close $fh;
    return undef;
}

sub _php_constraint_ok {
    my ( $constraint, $xy ) = @_;
    # Best effort, one direction only: is the selected PHP too OLD for the
    # app's composer.json PHP constraint? Understands ">=8.2", "^8.0",
    # "~8.1", "8.2", "8.2.*". Returns 1 (ok), 0 (too old), undef (nothing
    # parsable). Upper bounds ("<9.0") are ignored: running newer is not
    # this check's problem.
    if ( !defined $constraint || $constraint eq '' ) {
        return undef;
    }
    my $have = int( $xy / 10 ) + ( $xy % 10 ) / 100;
    my $parsed = 0;
    for my $part ( split /\s*\|\|\s*|\s+/, $constraint ) {
        next if $part eq '' || $part eq '*';
        if ( $part =~ /^(>=?|~|\^)?\s*(\d+)(?:\.(\d+))?/ ) {
            my $v = $2 + ( $3 // 0 ) / 100;
            if ( $have < $v - 0.0001 ) {
                return 0;
            }
            $parsed = 1;
        }
    }
    return $parsed ? 1 : undef;
}

sub _friendly_artisan_error {
    my ( $approot, $php_xy, $res ) = @_;
    my $out = $res->{output} // '';
    if ( $out =~ /symlink\(\) has been disabled|function .*symlink.* is disabled|disable_functions/i ) {
        return 'disabled_symlink';
    }
    if ( $out =~ /permission denied/i ) {
        return 'permission';
    }
    if ( !-f "$approot/vendor/autoload.php" ) {
        return 'no_vendor';
    }
    my $key = _read_dotenv_key( $approot, 'APP_KEY' );
    if ( !defined $key || $key eq '' ) {
        return 'no_app_key';
    }
    return undef;
}

sub _app_composer_php_constraint {
    my ($approot) = @_;
    open my $fh, '<', "$approot/composer.json" or return undef;
    local $/;
    my $raw = <$fh>;
    close $fh;
    my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
    if ( $@ || ref $data ne 'HASH' || ref $data->{require} ne 'HASH' ) {
        return undef;
    }
    return $data->{require}{php};
}

sub _ensure_storage_link {
    my ($approot) = @_;
    # storage:link fallback: create public/storage -> ../storage/app/public.
    # Only when the target is missing, the source is a real in-app dir, and
    # nothing is replaced.
    my $link = "$approot/public/storage";
    my @lst = lstat $link;
    if (@lst) {
        return ( 0, 'public/storage already exists; left alone' );
    }
    for my $comp (qw(public storage storage/app storage/app/public)) {
        my $p = "$approot/$comp";
        my @cst = lstat $p;
        if ( !@cst ) {
            return ( 0, "$comp is missing; left alone" );
        }
        if ( -l _ ) {
            return ( 0, "$comp is a symlink; left alone" );
        }
        if ( !-d _ ) {
            return ( 0, "$comp is not a directory; left alone" );
        }
    }
    if ( symlink( '../storage/app/public', $link ) ) {
        return ( 1, 'created public/storage link' );
    }
    return ( 0, "cannot create link: $!" );
}

sub _gate_app {
    my ( $result, $feature ) = @_;
    if ( !main::hasfeature($feature) ) {
        $result->error( '_ERROR_FEATURE', $feature );
        return;
    }
    if ( $Cpanel::CPDATA{'DEMO'} ) {
        $result->error( '_ERROR_DEMO_MODE', $feature );
        return;
    }
    if ( $> == 0 ) {
        $result->error('Refusing to run as root.');
        return;
    }
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_list - Detected apps plus manually added folders.
#-------------------------------------------------------------------------------------------------
sub app_helper_list {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my $detected = eval { _scan_detected_apps($home) };
    if ($@) {
        $result->error( 'App scan failed: [_1].', 'engine error' );
        return;
    }
    # One domain enumeration per list; each row carries the domains
    # mapped to it (same _mapped_domains boundary rule as the .env/.htaccess
    # code). Failure is honest: rows get an empty list.
    my @all_domains = eval { _user_domains($user) };
    my %seen;
    my @apps;
    for my $rec ( @{$detected} ) {
        my $rel = $rec->{path};
        $seen{$rel} = 1;
        push @apps, {
            path => $rel, source => 'detected', framework_version => $rec->{framework_version} // '',
            htaccess => _htaccess_status("$home/$rel"),
            domains => _app_domain_names( $user, "$home/$rel", \@all_domains ),
        };
    }
    for my $rel ( @{ _read_added_apps($home) } ) {
        next if exists $seen{$rel};
        $seen{$rel} = 1;
        push @apps, {
            path => $rel, source => 'added', framework_version => '',
            htaccess => _htaccess_status("$home/$rel"),
            domains => _app_domain_names( $user, "$home/$rel", \@all_domains ),
        };
    }
    # Versions for added folders that turn out to have markers too.
    if ( @apps ) {
        my %by_path = map { $_->{path} => $_ } @apps;
        for my $rec ( @{$detected} ) {
            if ( exists $by_path{ $rec->{path} } ) {
                $by_path{ $rec->{path} }{framework_version} = $rec->{framework_version} // '';
            }
        }
    }
    $result->data( { user => $user, apps => \@apps } );
    return 1;
}

sub _env_verdict {
    my ( $success, $status, $content, $url, $capped ) = @_;
    # Pure mapping (unit-tested): never returns the body, only verdict+note.
    # $capped means only the first ENV_CHECK_MAX_BYTES bytes were classified.
    $capped = $capped ? 1 : 0;
    my $body = ref $content ? '' : ( $content // '' );
    if ( !$success && $status == 599 && !$capped ) {
        return ( 'unknown', $url =~ m{^https:} ? 'could not verify (TLS)' : 'request failed' );
    }
    if ( !$success ) {
        if ( $status == 401 || $status == 403 || $status == 404 || $status == 410 ) {
            return ( 'safe', '' );
        }
        if ( $status >= 300 && $status < 400 ) {
            return ( $body =~ /APP_KEY=/ ? 'critical' : 'safe', '' );
        }
        return ( 'unknown', '' );
    }
    if ( $body =~ /^\s*APP_(KEY|ENV|NAME)=/m ) {
        return ( 'critical', '' );
    }
    if ($capped) {
        return ( 'unknown', 'response exceeded the read cap' );
    }
    return ( 'unknown', '' );
}

sub _http_get_capped {
    my ( $ua, $url ) = @_;
    # GET with a read cap enforced in data_callback (HTTP::Tiny's max_size
    # would discard the status code, hiding large-but-public bodies).
    # Returns ( {success,status}, capped_bool, body_prefix ). Never dies and
    # never returns more than the cap; the body is for classification only.
    my ( $buf, $capped, $cb_status ) = ( '', 0, 0 );
    my $resp = eval {
        $ua->get(
            $url,
            {
                data_callback => sub {
                    my ( $chunk, $r ) = @_;
                    if ( ref $r eq 'HASH' && defined $r->{status} ) {
                        $cb_status = $r->{status};
                    }
                    if ( length($buf) + length( $chunk // '' ) > $ENV_CHECK_MAX_BYTES ) {
                        my $room = $ENV_CHECK_MAX_BYTES - length($buf);
                        $buf .= substr( $chunk, 0, $room ) if $room > 0;
                        $capped = 1;
                        die { usertools_read_cap => 1 };
                    }
                    $buf .= $chunk;
                    return;
                },
            }
        );
    };
    if ( my $ex = $@ ) {
        if ( ref $ex eq 'HASH' && $ex->{usertools_read_cap} ) {
            my $ok = ( $cb_status >= 200 && $cb_status < 300 ) ? 1 : 0;
            return ( { success => $ok, status => $cb_status }, 1, $buf );
        }
        return ( { success => 0, status => 599 }, 0, '' );
    }
    if ( !defined $resp || ref $resp ne 'HASH' ) {
        return ( { success => 0, status => 599 }, 0, '' );
    }
    return ( $resp, 0, $buf );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_add / app_helper_remove - Manage the manual folder list
#   (~/.cpanel/usertools/apps.json, 0600, max 20 entries).
#-------------------------------------------------------------------------------------------------
sub app_helper_add {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($path) = $args->get('path');
    my ( $rel, $err ) = _validate_app_path( $home, $path );
    if ( !defined $rel ) {
        $result->error( 'Invalid folder: [_1].', $err );
        return;
    }
    my $detected = eval { _scan_detected_apps($home) };
    if ($@) {
        $result->error( 'App scan failed: [_1].', 'engine error' );
        return;
    }
    my %known = map { $_ => 1 } ( ( map { $_->{path} } @{$detected} ), @{ _read_added_apps($home) } );
    if ( $known{$rel} ) {
        $result->error( 'Folder already listed: [_1].', $rel );
        return;
    }
    my $added = _read_added_apps($home);
    if ( @{$added} >= $MAX_ADDED_APPS ) {
        $result->error( 'Too many manual folders (max [_1]).', "$MAX_ADDED_APPS" );
        return;
    }
    push @{$added}, $rel;
    if ( !_write_added_apps( $home, $added ) ) {
        $result->error('Unable to save the folder list.');
        return;
    }
    _activity_log( $home, 'app_helper', 'add app',
        { path => $rel }, { fn => 'app_helper_remove', args => { path => $rel } } );
    $result->data( { user => $user, path => $rel, added => scalar @{$added} } );
    return 1;
}

sub app_helper_remove {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($path) = $args->get('path');
    my $rel = _normalize_rel($path);
    my @kept = grep { $_ ne ( $rel // '' ) } @{ _read_added_apps($home) };
    if ( !_write_added_apps( $home, \@kept ) ) {
        $result->error('Unable to save the folder list.');
        return;
    }
    _activity_log( $home, 'app_helper', 'remove app',
        { path => $rel }, { fn => 'app_helper_add', args => { path => $rel } } );
    $result->data( { user => $user, removed => $path, added => scalar @kept } );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_artisan {app, command} - Run one whitelisted Artisan command
#   as the user (argv list, no shell; cwd = app root; 120 s process-group
#   timeout; minimal environment; one job per app). No other arguments exist.
#-------------------------------------------------------------------------------------------------
sub app_helper_artisan {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($command) = $args->get('command');
    if ( !defined $command || !$ARTISAN_COMMANDS{$command} ) {
        $result->error( 'Invalid command: [_1].', 'must be a listed maintenance command' );
        return;
    }
    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($php_version) = $args->get('php_version');
    my ( $php_bin, $php_err, $php_source );
    if ( defined $php_version && $php_version ne '' ) {
        ( $php_bin, $php_err ) = _select_php_bin($php_version);
        $php_source = 'selected';
    }
    else {
        ( $php_bin, $php_err, $php_source ) = _select_php_for_app( $user, $approot );
    }
    if ( !defined $php_bin ) {
        $result->error( 'No PHP available: [_1].', $php_err );
        return;
    }
    if ( !-f "$approot/vendor/autoload.php" ) {
        $result->data(
            {
                user => $user, app => $app_param, command => $command,
                ok => 0, friendly => 'no_vendor',
                detail => 'vendor/ is missing. Run composer install for this app first.',
                output => '', exit => -1, truncated => 0, timed_out => 0,
            }
        );
        return 1;
    }
    if ( $php_bin =~ m{/ea-php(\d\d)/} ) {
        my $constraint = _app_composer_php_constraint($approot);
        my $cok = _php_constraint_ok( $constraint, $1 );
        if ( defined $cok && $cok == 0 ) {
            $result->data(
                {
                    user => $user, app => $app_param, command => $command,
                    ok => 0, friendly => 'php_too_old',
                    detail => 'The selected PHP is older than this app needs. Pick a newer PHP version for its domain.',
                    output => '', exit => -1, truncated => 0, timed_out => 0,
                    php_bin => $php_bin, php_source => $php_source,
                }
            );
            return 1;
        }
    }
    my $rel = substr( $approot, length("$home/") );
    my $lock_path = _artisan_lock_path( $home, $rel );
    eval { make_path( "$home/.cpanel/usertools", { mode => 0700 } ) };
    open my $lock_fh, '>>', $lock_path or do {
        $result->error( 'Cannot lock app: [_1].', "$!" );
        return;
    };
    if ( !flock( $lock_fh, LOCK_EX | LOCK_NB ) ) {
        close $lock_fh;
        $result->data(
            {
                user => $user, app => $app_param, command => $command,
                ok => 0, friendly => 'busy',
                detail => 'Another Artisan command is already running for this app.',
                output => '', exit => -1, truncated => 0, timed_out => 0,
            }
        );
        return 1;
    }
    my $timeout = defined $TEST_ARTISAN_TIMEOUT ? $TEST_ARTISAN_TIMEOUT : $ARTISAN_TIMEOUT;
    my $res = _spawn_sync(
        [ $php_bin, "$approot/artisan", $command ], $approot,
        { PATH => '/usr/local/bin:/usr/bin:/bin', HOME => $home, LANG => 'C.UTF-8' },
        $timeout, $ARTISAN_OUTPUT_CAP,
    );
    close $lock_fh;
    my $failed = $res->{timed_out} || $res->{exit} != 0;
    my ( $friendly, $detail ) = ( undef, '' );
    if ( $res->{error} ) {
        $detail = 'Could not start the command.';
    }
    elsif ($failed) {
        $friendly = _friendly_artisan_error( $approot, 0, $res );
    }
    my $fallback = undef;
    if ( $failed && $command eq 'storage:link' && defined $friendly && $friendly eq 'disabled_symlink' ) {
        my ( $made, $note ) = _ensure_storage_link($approot);
        $fallback = { created => $made ? 1 : 0, detail => $note };
    }
    my %friendly_text = (
        disabled_symlink => 'PHP has symlink() disabled, so storage:link cannot link.',
        permission       => 'Permission denied. Check the app folder permissions (Fix app permissions may help).',
        no_vendor        => 'vendor/ is missing. Run composer install for this app first.',
        no_app_key       => 'APP_KEY is missing or empty in .env.',
    );
    $result->data(
        {
            user => $user, app => $app_param, command => $command,
            php_bin => $php_bin, php_source => $php_source,
            ok => $failed ? 0 : 1,
            friendly => $friendly,
            detail => $detail ne '' ? $detail
                : ( defined $friendly ? ( $friendly_text{$friendly} // $friendly ) : '' ),
            fallback => $fallback,
            resource_hint => _lve_hint($res),
            output => $res->{output}, exit => $res->{exit} + 0,
            truncated => $res->{truncated} ? 1 : 0,
            timed_out => $res->{timed_out} ? 1 : 0,
        }
    );
    _activity_log( $home, 'app_helper', 'run artisan',
        { app => $app_param, command => $command, exit => $res->{exit} + 0 },
        undef );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_fix_perms {app} - Dry-run bulk job scoped to the app plus
#   writability report. The page confirms, then starts the real bulk job.
#-------------------------------------------------------------------------------------------------
sub app_helper_fix_perms {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my $py  = $TEST_ENGINE_BIN // $ENGINE_PYTHON;
    my $bin = $TEST_ENGINE     // $ENGINE_PATH;
    my @cmd = ( $py, $bin, 'chmod', '--scope', $approot, '--dry-run', '--no-undo' );
    if ( ( $ENV{USERTOOLS_TESTING} // '' ) eq '1' && defined $TEST_HOME ) {
        push @cmd, '--home', $home;
    }
    open my $fh, '-|', @cmd or do {
        $result->error( 'Cannot preview permissions: [_1].', "$!" );
        return;
    };
    local $/;
    my $out = <$fh>;
    close $fh;
    my $preview = eval { JSON::PP->new()->decode( $out // '' ) };
    if ( $@ || ref $preview ne 'HASH' ) {
        $result->error('Permission preview failed.');
        return;
    }
    $result->data(
        {
            user  => $user,
            app   => $app_param,
            scope => $approot,
            preview_counts => $preview->{counts} // {},
            storage => {
                exists   => -d "$approot/storage" ? 1 : 0,
                writable => -w "$approot/storage" ? 1 : 0,
            },
            bootstrap_cache => {
                exists   => -d "$approot/bootstrap/cache" ? 1 : 0,
                writable => -w "$approot/bootstrap/cache" ? 1 : 0,
            },
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_env_check {app} - Probe the app's own domains for .env leaks.
#-------------------------------------------------------------------------------------------------
sub app_helper_env_check {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my $probe = _env_probe_app( $user, $approot );
    if ( defined $probe->{note} ) {
        $result->data(
            {
                user => $user, app => $app_param, checked => [],
                note => $probe->{note},
            }
        );
        return 1;
    }
    $result->data( { user => $user, app => $app_param, checked => $probe->{checked} } );
    return 1;
}

sub _env_probe_app {
    my ( $user, $approot ) = @_;
    # Shared prober behind app_helper_env_check and the post-apply check in
    # app_helper_htaccess_apply. Returns {checked=>[...]} or {note=>...}
    # when nothing could be checked. Never returns response bodies.
    my @all = _user_domains($user);
    if ( !@all ) {
        return { note => 'Cannot list domains for this account, so nothing was checked.' };
    }
    my @mapped = _mapped_domains( $user, $approot, \@all );
    if ( !@mapped ) {
        return { note => 'No website is mapped to this app, so nothing was checked.' };
    }
    # At most 10 mapped domains inside a 30 s overall budget (a full
    # home scan per call is already the expensive part; unbounded outbound
    # probing must not outlast the UAPI request).
    my $budget = defined $TEST_ENV_BUDGET_SECONDS ? $TEST_ENV_BUDGET_SECONDS : 30;
    my @targets = splice @mapped, 0, 10;
    my @deferred = map { $_->{domain} } @mapped;
    require HTTP::Tiny;
    my $ua = HTTP::Tiny->new(
        timeout      => $ENV_CHECK_TIMEOUT,
        max_redirect => 0,
        verify_SSL   => 1,
    );
    my @checked;
    my $t0 = time();
    for my $d (@targets) {
        if ( time() - $t0 > $budget ) {
            push @deferred, $d->{domain};
            next;
        }
        my @urls = ( "https://$d->{domain}/.env" );
        my $docroot = $d->{documentroot} // '';
        if ( $docroot ne '' && $approot ne $docroot && index( $approot, "$docroot/" ) == 0 ) {
            my $sub = substr( $approot, length($docroot) );
            $sub =~ s{^/}{};
            if ( $sub ne '' ) {
                push @urls, "https://$d->{domain}/$sub/.env";
            }
        }
        for my $url (@urls) {
            my ( $resp, $capped, $body ) = _http_get_capped( $ua, $url );
            my ( $verdict, $note ) = _env_verdict(
                $resp->{success} ? 1 : 0, $resp->{status} // 0,
                $body, $url, $capped );
            push @checked,
              { url => $url, status => $resp->{status} // 0, verdict => $verdict, note => $note };
        }
    }
    for my $domain (@deferred) {
        push @checked,
          { url => "https://$domain/.env", status => 0, verdict => 'unknown', note => 'not checked (time budget)' };
    }
    return { checked => \@checked };
}

sub _http_head_status {
    my ($url) = @_;
    # Single homepage probe for the post-apply check (isolated for tests).
    # Returns the HTTP status or 0 when unreachable. Connection, DNS and TLS
    # failures surface as 599 (HTTP::Tiny), never 0 — see _is_down_status.
    require HTTP::Tiny;
    my $ua = HTTP::Tiny->new(
        timeout      => $ENV_CHECK_TIMEOUT,
        max_redirect => 0,
        verify_SSL   => 1,
    );
    my $resp = eval { $ua->request( 'HEAD', $url ) };
    if ( $@ || ref $resp ne 'HASH' ) {
        return 0;
    }
    return $resp->{status} // 0;
}

sub _is_down_status {
    my ($status) = @_;
    # Only a REAL failure restores files: 403 or 500-598. Status 0 and
    # 599 mean "could not check the homepage" (connection/DNS/TLS — common
    # before AutoSSL) and only warn; 3xx counts as OK since the guard
    # follows no redirects.
    $status = 0 unless defined $status;
    if ( $status == 403 ) {
        return 1;
    }
    if ( $status >= 500 && $status <= 598 ) {
        return 1;
    }
    return 0;
}

sub _nested_domains {
    my ( $user, $approot, $recs_ar ) = @_;
    # Domains served from INSIDE the app folder but NOT from <app>/public:
    # writing the root deny-all would 403 them, since .htaccess files
    # apply to child paths. Boundary-safe.
    my @recs = defined $recs_ar ? @{$recs_ar} : _user_domains($user);
    my $pub  = "$approot/public";
    my @out;
    for my $r (@recs) {
        my $doc = ref $r eq 'HASH' ? ( $r->{documentroot} // '' ) : '';
        my $name = ref $r eq 'HASH' ? ( $r->{domain} // '' ) : '';
        next if $doc eq '' || $name eq '';
        next unless index( $doc, "$approot/" ) == 0;
        next if $doc eq $pub || index( $doc, "$pub/" ) == 0;
        push @out, { domain => $name, documentroot => $doc };
    }
    my @sorted = sort { $a->{domain} cmp $b->{domain} } @out;
    return @sorted;
}

sub _guard_homepages {
    my ( $user, $approot ) = @_;
    # Post-apply guard: HEAD every domain that could be affected —
    # the app's mapped domains plus any domain under the app root — capped
    # at 10 inside the 30 s budget. Returns {failed, domain, status,
    # checked, warning}: failed is set only by a real 403/500-598; 0/599
    # only warns. first_domain/first_status describe the first probe (kept
    # for the single-homepage response shape).
    my @all = _user_domains($user);
    my %seen;
    my @targets;
    for my $d ( _mapped_domains( $user, $approot, \@all ) ) {
        next if $seen{ $d->{domain} }++;
        push @targets, $d->{domain};
    }
    for my $r (@all) {
        my $doc = $r->{documentroot} // '';
        next unless $doc ne '' && ( $doc eq $approot || index( $doc, "$approot/" ) == 0 );
        next if $seen{ $r->{domain} }++;
        push @targets, $r->{domain};
    }
    @targets = sort @targets;
    my $budget = defined $TEST_ENV_BUDGET_SECONDS ? $TEST_ENV_BUDGET_SECONDS : 30;
    my $t0 = time();
    my ( $failed, $fdomain, $fstatus, $warning, $n ) = ( 0, undef, 0, '', 0 );
    my ( $first_domain, $first_status );
    my $cap = @targets > 10 ? 10 : scalar @targets;
    for my $i ( 0 .. $cap - 1 ) {
        last if time() - $t0 > $budget;
        my $domain = $targets[$i];
        my $st = _http_head_status("https://$domain/");
        if ( !defined $first_domain ) {
            $first_domain = $domain;
            $first_status = $st;
        }
        $n++;
        if ( _is_down_status($st) ) {
            $failed  = 1;
            $fdomain = $domain;
            $fstatus = $st;
            last;
        }
        if ( ( $st == 0 || $st == 599 ) && $warning eq '' ) {
            $warning = "Could not check https://$domain/ (network or TLS); not treated as a failure.";
        }
    }
    return {
        failed => $failed, domain => $fdomain, status => $fstatus,
        checked => $n, warning => $warning,
        first_domain => $first_domain, first_status => defined $first_status ? $first_status : 0,
    };
}

# ---------------------------------------------------------------------------
# App Helper (tool E): addon/subdomain docroots, the .htaccess
# generator, and the primary-domain switch. All file writes run as the user;
# the only privileged step (primary docroot) goes through the Admin module.
# ---------------------------------------------------------------------------

sub _uapi_result_status {
    my ($res) = @_;
    # Reads a UAPI call result. On a real server Cpanel::API::execute
    # returns a blessed Cpanel::Result, read through methods; plain hashes
    # (tests, and any unblessed reply) are read by key. Anything else is
    # unreadable. The exact Cpanel::Result method surface (status / errors /
    # errors_as_string / data) varies, so the defensive order below works
    # whether errors arrives
    # as a list or a string.
    # Returns ($status_or_undef, $reason).
    if ( ref $res ) {
        if ( eval { $res->can('status') } ) {
            my $st     = eval { $res->status() };
            my $reason = 'unknown error';
            my $errs   = eval { $res->errors() };
            if ( ref $errs eq 'ARRAY' && defined $errs->[0] ) {
                $reason = "$errs->[0]";
            }
            else {
                my $es = eval { $res->errors_as_string() };
                if ( defined $es && $es ne '' ) {
                    $reason = "$es";
                }
            }
            return ( $st, $reason );
        }
        if ( ref $res eq 'HASH' ) {
            my $reason = 'unknown error';
            if ( ref $res->{errors} eq 'ARRAY' && defined $res->{errors}[0] ) {
                $reason = "$res->{errors}[0]";
            }
            return ( $res->{status}, $reason );
        }
    }
    return ( undef, 'unknown error' );
}

sub _uapi_changedocroot {
    my ( $domain, $rel_docroot ) = @_;
    # One-click "point this domain at <app>/public" through the official UAPI
    # SubDomain::changedocroot, called IN-PROCESS as the user (this code
    # already runs as the user inside UAPI, via the documented
    # Cpanel::API::execute — no uapi CLI round-trip, no username parameter
    # because caller identity is the process, no shell).
    # Documented parameters (UAPI v11.138,
    # https://api.docs.cpanel.net/specifications/cpanel.openapi/subdomains/subdomain-changedocroot):
    # `domain` (the full domain name, e.g. sub.example.com) + `docroot` (the
    # new docroot home-relative, e.g. public_html/myapp/public). That is NOT
    # the deprecated API 2 sibling, which takes subdomain+rootdomain+dir —
    # do not mix them up. Success is status==1; reasons come from errors[].
    # Not for primary domains (refused by callers; those go through WHM
    # set_primary_domain_docroot). $rel_docroot is derived server-side from
    # <app>/public, never user input.
    my $res = eval {
        Cpanel::API::execute( 'SubDomain', 'changedocroot',
            { domain => $domain, docroot => $rel_docroot } );
    };
    if ( $@ || !defined $res || !ref $res ) {
        return ( 0, 'SubDomain changedocroot returned an unreadable reply' );
    }
    my ( $st, $reason ) = _uapi_result_status($res);
    if ( !defined $st ) {
        return ( 0, 'SubDomain changedocroot returned an unreadable reply' );
    }
    if ( $st == 1 ) {
        return ( 1, '' );
    }
    return ( 0, substr( $reason, 0, 200 ) );
}

sub _restrict_docroots_to_public_html {
    my ($path) = @_;
    # The "Restrict document roots to public_html" tweak (WHM Tweak Settings
    # -> Domains) is stored as `publichtmlsubsonly` in /var/cpanel/cpanel.config.
    # Absent or unreadable means off here — the server API remains the final
    # authority and its errors pass through honestly. Check by hand with:
    # grep publichtmlsubsonly /var/cpanel/cpanel.config
    $path = defined $TEST_CPANEL_CONFIG ? $TEST_CPANEL_CONFIG : '/var/cpanel/cpanel.config'
      unless defined $path;
    if ( open my $fh, '<', $path ) {
        while ( my $line = <$fh> ) {
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '' || $line =~ /^[#;]/;
            next unless $line =~ /=/;
            my ( $k, $v ) = split /=/, $line, 2;
            $k =~ s/^\s+|\s+$//g;
            $v =~ s/^\s+|\s+$//g;
            if ( lc($k) eq 'publichtmlsubsonly' ) {
                close $fh;
                return $v =~ /^(1|yes|on|true)$/i ? 1 : 0;
            }
        }
        close $fh;
    }
    return 0;
}

sub _docroot_journal_file {
    my ($home) = @_;
    return "$home/.cpanel/usertools/docroot.json";
}

sub _read_docroot_journal {
    my ($home) = @_;
    my $file = _docroot_journal_file($home);
    if ( open my $fh, '<', $file ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' && ref $data->{changes} eq 'HASH' ) {
            return $data->{changes};
        }
    }
    return {};
}

sub _write_docroot_journal {
    my ( $home, $changes_hr ) = @_;
    my $dir = "$home/.cpanel/usertools";
    eval { make_path( $dir, { mode => 0700 } ) };
    return 0 if $@;
    my $file = _docroot_journal_file($home);
    my $tmp  = "$file.tmp.$$";
    my $fh;
    if ( !open $fh, '>', $tmp ) {
        return 0;
    }
    print $fh JSON::PP->new()->canonical(1)->encode( { changes => $changes_hr } );
    close $fh;
    chmod 0600, $tmp;
    return rename( $tmp, $file ) ? 1 : 0;
}

sub _docroot_plan {
    my ( $user, $home, $app_param, $domain_param ) = @_;
    # Shared validation for preview/set. Returns ($plan, undef) or
    # (undef, $error). The new docroot is always <app>/public, derived
    # server-side and never user-supplied.
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        return ( undef, $app_err );
    }
    if ( !defined $domain_param || $domain_param eq '' ) {
        return ( undef, 'domain is required' );
    }
    ( my $domain = $domain_param ) =~ s/^\s+|\s+$//g;
    if ( $domain !~ /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/ ) {
        return ( undef, 'unknown domain for this account' );
    }
    my ( $recs, $main_domain ) = _user_domain_info($user);
    my ($rec) = grep { lc( $_->{domain} ) eq lc($domain) } @{$recs};
    if ( !defined $rec ) {
        return ( undef, 'unknown domain for this account' );
    }
    $domain = $rec->{domain};
    if ( defined $main_domain && lc($domain) eq lc($main_domain) ) {
        return ( undef, 'the main domain cannot be pointed here; use the main-domain switch below' );
    }
    if ( defined $rec->{kind} && $rec->{kind} ne 'addon' && $rec->{kind} ne 'sub' ) {
        return ( undef, 'only addon domains and subdomains can be pointed at an app' );
    }
    my $rel = $approot eq $home ? '' : substr( $approot, length("$home/") );
    my $new_rel = $rel eq '' ? 'public' : "$rel/public";
    if ( !-d "$approot/public" ) {
        return ( undef, 'this app has no public folder yet' );
    }
    my $restricted = _restrict_docroots_to_public_html();
    my $under_html = ( $approot eq "$home/public_html" || index( $approot, "$home/public_html/" ) == 0 ) ? 1 : 0;
    my $plan = {
        approot    => $approot,
        rel        => $rel,
        domain     => $domain,
        old_docroot => $rec->{documentroot},
        new_docroot => "$home/$new_rel",
        new_rel    => $new_rel,
        restricted => $restricted ? 1 : 0,
    };
    if ( $restricted && !$under_html ) {
        $plan->{allowed} = 0;
        $plan->{reason}  = 'document roots are restricted to public_html on this server, '
          . 'but this app lives outside it. Move the app under public_html/ or ask your host.';
        return ( $plan, undef );
    }
    $plan->{allowed} = 1;
    return ( $plan, undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_docroot_preview / app_helper_set_docroot / app_helper_undo_docroot
#-------------------------------------------------------------------------------------------------
sub app_helper_docroot_preview {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param)    = $args->get('app');
    my ($domain_param) = $args->get('domain');
    my ( $plan, $err ) = _docroot_plan( $user, $home, $app_param, $domain_param );
    if ( !defined $plan ) {
        $result->error( 'Invalid domain change: [_1].', $err );
        return;
    }
    $result->data(
        {
            user => $user, app => $app_param,
            domain => $plan->{domain}, old_docroot => $plan->{old_docroot},
            new_docroot => $plan->{new_docroot}, restricted => $plan->{restricted},
            allowed => $plan->{allowed},
            $plan->{allowed} ? () : ( reason => $plan->{reason} ),
        }
    );
    return 1;
}

sub app_helper_set_docroot {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param)    = $args->get('app');
    my ($domain_param) = $args->get('domain');
    my ( $plan, $err ) = _docroot_plan( $user, $home, $app_param, $domain_param );
    if ( !defined $plan ) {
        $result->error( 'Invalid domain change: [_1].', $err );
        return;
    }
    if ( !$plan->{allowed} ) {
        ( my $reason = $plan->{reason} // '' ) =~ s/\.\z//;
        $result->error( 'Domain change refused: [_1].', $reason );
        return;
    }
    my ( $ok, $uerr ) = _uapi_changedocroot( $plan->{domain}, $plan->{new_rel} );
    if ( !$ok ) {
        $result->error( 'Domain change failed: [_1].', $uerr );
        return;
    }
    my $changes = _read_docroot_journal($home);
    $changes->{ $plan->{domain} } = {
        old_docroot => $plan->{old_docroot}, new_docroot => $plan->{new_docroot}, at => time(),
    };
    if ( !_write_docroot_journal( $home, $changes ) ) {
        $result->error('Domain pointed, but the undo record could not be saved.');
        return;
    }
    $result->data(
        {
            user => $user, app => $app_param,
            domain => $plan->{domain}, old_docroot => $plan->{old_docroot},
            new_docroot => $plan->{new_docroot},
        }
    );
    _activity_log( $home, 'app_helper', 'set docroot',
        { app => $app_param, domain => $plan->{domain} },
        { fn => 'app_helper_undo_docroot',
          args => { domain => $plan->{domain} } } );
    return 1;
}

sub app_helper_undo_docroot {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($domain_param) = $args->get('domain');
    if ( !defined $domain_param || $domain_param eq '' ) {
        $result->error( 'Invalid domain: [_1].', 'domain is required' );
        return;
    }
    ( my $domain = $domain_param ) =~ s/^\s+|\s+$//g;
    my $changes = _read_docroot_journal($home);
    my ($key) = grep { lc($_) eq lc($domain) } keys %{$changes};
    if ( !defined $key ) {
        $result->error('Nothing to undo for this domain.');
        return;
    }
    my $old = $changes->{$key}{old_docroot};
    if ( !defined $old || $old eq '' ) {
        $result->error('Nothing to undo for this domain.');
        return;
    }
    my $old_rel;
    if ( $old eq $home ) {
        $old_rel = '';
    }
    elsif ( index( $old, "$home/" ) == 0 ) {
        $old_rel = substr( $old, length("$home/") );
    }
    else {
        $result->error('The previous docroot is outside your home directory; ask your host.');
        return;
    }
    if ( $old_rel eq '' ) {
        $result->error('The previous docroot cannot be restored through this switch; ask your host.');
        return;
    }
    my ( $ok, $uerr ) = _uapi_changedocroot( $key, $old_rel );
    if ( !$ok ) {
        $result->error( 'Undo failed: [_1].', $uerr );
        return;
    }
    delete $changes->{$key};
    _write_docroot_journal( $home, $changes );
    $result->data( { user => $user, domain => $key, restored => $old } );
    _activity_log( $home, 'app_helper', 'undo docroot',
        { domain => $key }, undef );
    return 1;
}

# ---------------------------------------------------------------------------
# .htaccess generator (written as the user, with preview, backup and undo).
# Our content lives only between the UserTools markers; every other line —
# cPanel-generated blocks included — is preserved verbatim, in order.
# ---------------------------------------------------------------------------

our $HT_BEGIN = '# BEGIN UserTools';
our $HT_END   = '# END UserTools';

our $HT_MAX_BYTES = 65536;

sub _ht_exempt_public {
    my ( $user, $home, $approot ) = @_;
    # Source of the <If> path: Apache compares %{REQUEST_FILENAME}
    # against the path AS CONFIGURED in the vhost, so a resolved realpath
    # can miss (e.g. /home -> /home2, custom HOMEDIR). Prefer the exact
    # DomainInfo string when a mapped domain's documentroot equals
    # <app>/public; otherwise fall back to getpwnam home + the home-relative
    # app path. Never the realpath. Same charset rule as the renderer.
    # Returns ($exempt_abs, undef) or (undef, $error).
    my ($recs) = _user_domain_info($user);
    my $want = "$approot/public";
    for my $r ( sort { ( $a->{domain} // '' ) cmp( $b->{domain} // '' ) } @{$recs} ) {
        my $doc = ref $r eq 'HASH' ? ( $r->{documentroot} // '' ) : '';
        if ( $doc ne '' && $doc eq $want ) {
            return ( $doc, undef );
        }
    }
    my @pw = getpwnam($user);
    my $ghome = @pw ? $pw[7] : undef;
    if ( !defined $ghome || $ghome eq '' || $ghome eq '/' ) {
        return ( undef, 'unsafe app path for the root lock' );
    }
    my $rel;
    if ( $approot eq $home ) {
        $rel = '';
    }
    elsif ( index( $approot, "$home/" ) == 0 ) {
        $rel = substr( $approot, length("$home/") );
    }
    else {
        return ( undef, 'unsafe app path for the root lock' );
    }
    my $exempt = $rel eq '' ? "$ghome/public" : "$ghome/$rel/public";
    if ( $exempt !~ m{^[A-Za-z0-9/_.-]+$} ) {
        return ( undef, 'unsafe app path for the root lock' );
    }
    return ( $exempt, undef );
}

sub _ht_root_block_for {
    my ($exempt) = @_;
    # Renders the lock for an already-chosen exempt path. Only path
    # characters in [A-Za-z0-9/_.-] are accepted and '.' is regex-escaped,
    # so the interpolated m#...# cannot break out (this also keeps '#' out,
    # the regex delimiter). Returns ($block, undef) or (undef, $error).
    if ( !defined $exempt || $exempt eq '' || $exempt !~ m{^[A-Za-z0-9/_.-]+$} ) {
        return ( undef, 'unsafe app path for the root lock' );
    }
    ( my $re = $exempt ) =~ s/\./\\./g;
    my $block = join( "\n",
        '# Managed by UserTools App Helper: deny everything except the public folder.',
        '# Only lines between the UserTools markers are ever rewritten.',
        'Options -Indexes',
        "<If \"%{REQUEST_FILENAME} !~ m#^$re(/|\$)#\">",
        '    Require all denied',
        '</If>',
    ) . "\n";
    return ( $block, undef );
}

sub _ht_root_block {
    my ( $user, $home, $approot ) = @_;
    # Root lock with a public-subtree exemption: the deny-all no
    # longer depends on our public file surviving deploys. Resolves the
    # exempt path first, then renders.
    my ( $exempt, $err ) = _ht_exempt_public( $user, $home, $approot );
    if ( !defined $exempt ) {
        return ( undef, $err );
    }
    return _ht_root_block_for($exempt);
}

sub _ht_public_block {
    my (%o) = @_;
    # Front-controller rules below are derived from Laravel's stock
    # public/.htaccess (MIT; see THIRD_PARTY_NOTICES.md). Optional helpers
    # are checkbox-driven.
    my @b = (
        '# Managed by UserTools App Helper: grant access to the public folder,',
        '# then Laravel front-controller rules plus the helpers you picked.',
        'Require all granted',
        '',
        '<FilesMatch "^\\.">',
        '    Require all denied',
        '</FilesMatch>',
        '',
        '<IfModule mod_rewrite.c>',
        '    <IfModule mod_negotiation.c>',
        '        Options -MultiViews -Indexes',
        '    </IfModule>',
        '',
        '    RewriteEngine On',
        '',
    );
    if ( $o{auth} ) {
        push @b,
          (
            '    # Handle Authorization Header',
            '    RewriteCond %{HTTP:Authorization} .',
            '    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]',
            '',
          );
    }
    if ( $o{slash} ) {
        push @b,
          (
            '    # Redirect Trailing Slashes If Not A Folder...',
            '    RewriteCond %{REQUEST_FILENAME} !-d',
            '    RewriteCond %{REQUEST_URI} (.+)/$',
            '    RewriteRule ^ %1 [L,R=301]',
            '',
          );
    }
    if ( $o{nonwww} ) {
        push @b,
          (
            '    # Redirect www to the bare domain, keeping the scheme...',
            '    RewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]',
            '    RewriteRule ^ %{REQUEST_SCHEME}://%1%{REQUEST_URI} [L,R=301]',
            '',
          );
    }
    if ( $o{https} ) {
        push @b,
          (
            '    # Force HTTPS...',
            '    RewriteCond %{HTTPS} off',
            '    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
            '',
          );
    }
    if ( $o{indexphp} ) {
        push @b,
          (
            '    # Strip index.php from URLs...',
            '    RewriteCond %{THE_REQUEST} ^[A-Z]{3,}\\s/index\\.php [NC]',
            '    RewriteRule ^index\\.php/?(.*)$ /$1 [L,R=301]',
            '',
          );
    }
    push @b,
      (
        '    # Send Requests To Front Controller...',
        '    RewriteCond %{REQUEST_FILENAME} !-d',
        '    RewriteCond %{REQUEST_FILENAME} !-f',
        '    RewriteRule ^ index.php [L]',
        '</IfModule>',
      );
    if ( $o{expires} ) {
        push @b,
          (
            '',
            '<IfModule mod_expires.c>',
            '    ExpiresActive On',
            '    ExpiresByType image/jpeg "access plus 1 month"',
            '    ExpiresByType image/png "access plus 1 month"',
            '    ExpiresByType image/webp "access plus 1 month"',
            '    ExpiresByType text/css "access plus 1 month"',
            '    ExpiresByType application/javascript "access plus 1 month"',
            '    ExpiresByType application/json "access plus 1 hour"',
          );
        if ( $o{sitemap} ) {
            push @b,
              (
                '    <FilesMatch "^sitemap.*\\.xml$">',
                '        ExpiresDefault "access plus 1 hour"',
                '    </FilesMatch>',
              );
        }
        push @b, '</IfModule>';
        push @b,
          (
            '<IfModule mod_deflate.c>',
            '    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript application/json',
            '</IfModule>',
          );
    }
    elsif ( $o{sitemap} ) {
        push @b,
          (
            '',
            '<IfModule mod_expires.c>',
            '    <FilesMatch "^sitemap.*\\.xml$">',
            '        ExpiresDefault "access plus 1 hour"',
            '    </FilesMatch>',
            '</IfModule>',
          );
    }
    return join( "\n", @b ) . "\n";
}

sub _ht_opt {
    my ( $args, $name, $default ) = @_;
    my ($v) = $args->get($name);
    if ( !defined $v ) {
        return ( $default, undef );
    }
    if ( !ref $v && ( $v eq '1' || $v eq '0' ) ) {
        return ( $v eq '1' ? 1 : 0, undef );
    }
    if ( ref $v && eval { $v->isa('JSON::PP::Boolean') } ) {
        return ( $v ? 1 : 0, undef );
    }
    return ( undef, "invalid option $name" );
}

sub _ht_options {
    my ($args) = @_;
    # Defaults: non-www, trailing slash and expires/deflate on; the rest off.
    my %def = ( nonwww => 1, slash => 1, expires => 1, https => 0, indexphp => 0, auth => 0, sitemap => 0 );
    my %out;
    for my $k ( sort keys %def ) {
        my ( $v, $err ) = _ht_opt( $args, $k, $def{$k} );
        if ( defined $err ) {
            return ( undef, $err );
        }
        $out{$k} = $v;
    }
    return ( \%out, undef );
}

sub _ht_merge {
    my ( $current, $block ) = @_;
    # Insert or replace ONLY the marked section; every other line keeps its
    # bytes and order. Idempotent: re-applying the same block is a no-op.
    chomp $block;
    my @section = ( $HT_BEGIN, split( /\n/, $block ), $HT_END );
    if ( !defined $current ) {
        return join( "\n", @section ) . "\n";
    }
    my @lines = split( /\n/, $current );
    my ( $bi, $ei );
    for my $i ( 0 .. $#lines ) {
        if ( !defined $bi && $lines[$i] eq $HT_BEGIN ) {
            $bi = $i;
        }
        if ( $lines[$i] eq $HT_END ) {
            $ei = $i;
        }
    }
    if ( defined $bi && defined $ei && $ei > $bi ) {
        splice @lines, $bi, $ei - $bi + 1, @section;
    }
    else {
        if ( @lines && $lines[-1] ne '' ) {
            push @lines, '';
        }
        push @lines, @section;
    }
    return join( "\n", @lines ) . "\n";
}

sub _ht_diff {
    my ( $old, $new ) = @_;
    # Small honest preview diff (common prefix/suffix trim): '-' lines leave,
    # '+' lines arrive. Identical files report no changes.
    $old = '' unless defined $old;
    $new = '' unless defined $new;
    if ( $old eq $new ) {
        return '(no changes)';
    }
    my @a = split( /\n/, $old );
    my @b = split( /\n/, $new );
    my $pre = 0;
    while ( $pre < @a && $pre < @b && $a[$pre] eq $b[$pre] ) {
        $pre++;
    }
    my $suf = 0;
    while ( $suf < ( @a - $pre ) && $suf < ( @b - $pre ) && $a[ $#a - $suf ] eq $b[ $#b - $suf ] ) {
        $suf++;
    }
    my @out;
    if ( $pre + $suf < @a ) {
        push @out, map { "-$_" } @a[ $pre .. $#a - $suf ];
    }
    if ( $pre + $suf < @b ) {
        push @out, map { "+$_" } @b[ $pre .. $#b - $suf ];
    }
    return join( "\n", @out );
}

sub _htaccess_warnings {
    my ( $which, $content ) = @_;
    # Known weak patterns in the CURRENT file. The FilesMatch-on-vendor
    # pattern can never match a path; serving or rewriting from the app
    # root exposes vendor/, logs and dumps.
    my @w;
    $content = '' unless defined $content;
    if ( $which eq 'root' ) {
        if ( $content =~ /FilesMatch[^\n]*vendor\//i ) {
            push @w, 'Root .htaccess has a FilesMatch on vendor/, which can never match a path. '
              . 'Replace with the safe template.';
        }
        if ( $content =~ /RewriteRule[^\n]*public\// ) {
            push @w, 'Root .htaccess rewrites into public/ instead of denying the app root. '
              . 'Replace with the safe template.';
        }
        elsif ( $content =~ /RewriteCond[^\n]*REQUEST_FILENAME[^\n]*-[fd]/ && $content =~ /RewriteRule/ ) {
            push @w, 'Root .htaccess serves existing files directly instead of denying. '
              . 'Replace with the safe template.';
        }
    }
    return \@w;
}

sub _read_text_file {
    my ($path) = @_;
    # Returns the content, undef when missing, or dies on refusal/too-large.
    # Symlinks are never followed.
    my @st = lstat $path;
    if ( !@st ) {
        return undef;
    }
    if ( -l _ ) {
        die "refusing symlink";
    }
    if ( !-f _ ) {
        die "not a regular file";
    }
    if ( $st[7] > $HT_MAX_BYTES ) {
        die "file too large";
    }
    if ( open my $fh, '<', $path ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        return defined $raw ? $raw : '';
    }
    die "cannot read: $!";
}

sub _write_text_file {
    my ( $path, $content, $mode ) = @_;
    # Atomic write (tmp + rename) with an exact mode.
    $mode = 0644 unless defined $mode;
    my $tmp = "$path.usertools-new.$$";
    if ( open my $fh, '>', $tmp ) {
        print $fh $content;
        close $fh;
        chmod $mode, $tmp;
        if ( rename( $tmp, $path ) ) {
            return 1;
        }
        unlink $tmp;
    }
    return 0;
}

sub _ht_backup {
    my ($path) = @_;
    # Backup before apply: <file>.usertools-bak-<ts>, 0600, keep the last 3.
    # Returns the backup path, or undef when the file did not exist.
    if ( !-f $path ) {
        return undef;
    }
    my $base = "$path.usertools-bak-" . time();
    my $bak  = $base;
    my $n    = 0;
    while ( -e $bak ) {
        $n++;
        $bak = "$base-$n";
    }
    my $content = eval { _read_text_file($path) };
    if ( $@ || !defined $content ) {
        return undef;
    }
    if ( !_write_text_file( $bak, $content, 0600 ) ) {
        return undef;
    }
    my @all = sort glob "$path.usertools-bak-*";
    while ( @all > 3 ) {
        my $old = shift @all;
        unlink $old;
    }
    return $bak;
}

sub _ht_orig_journal_file {
    my ($home) = @_;
    return "$home/.cpanel/usertools/htaccess.json";
}

sub _read_ht_orig_journal {
    my ($home) = @_;
    my $file = _ht_orig_journal_file($home);
    if ( open my $fh, '<', $file ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' && ref $data->{files} eq 'HASH' ) {
            return $data->{files};
        }
    }
    return {};
}

sub _write_ht_orig_journal {
    my ( $home, $files_hr ) = @_;
    my $dir = "$home/.cpanel/usertools";
    eval { make_path( $dir, { mode => 0700 } ) };
    return 0 if $@;
    my $file = _ht_orig_journal_file($home);
    my $tmp  = "$file.tmp.$$";
    my $fh;
    if ( !open $fh, '>', $tmp ) {
        return 0;
    }
    print $fh JSON::PP->new()->canonical(1)->encode( { files => $files_hr } );
    close $fh;
    chmod 0600, $tmp;
    return rename( $tmp, $file ) ? 1 : 0;
}

sub _ht_home_rel {
    my ( $home, $path ) = @_;
    if ( $path eq $home ) {
        return '';
    }
    if ( index( $path, "$home/" ) == 0 ) {
        return substr( $path, length("$home/") );
    }
    return undef;
}

sub _ht_ensure_orig {
    my ( $home, $path ) = @_;
    # First-apply preservation: record the pre-UserTools state once per
    # file — {absent} when the file did not exist, else a 0600 copy at
    # <file>.usertools-orig that pruning never touches. Returns 1 on success
    # (or when already recorded); callers refuse the apply otherwise, so the
    # original can never be silently lost.
    my $rel = _ht_home_rel( $home, $path );
    if ( !defined $rel || $rel eq '' ) {
        return 0;
    }
    my $files = _read_ht_orig_journal($home);
    if ( exists $files->{$rel} ) {
        return 1;
    }
    if ( !-f $path ) {
        $files->{$rel} = { absent => 1 };
    }
    else {
        my $content = eval { _read_text_file($path) };
        if ( $@ || !defined $content ) {
            return 0;
        }
        my $orig = "$path.usertools-orig";
        if ( !_write_text_file( $orig, $content, 0600 ) ) {
            return 0;
        }
        $files->{$rel} = { orig => $orig };
    }
    return _write_ht_orig_journal( $home, $files ) ? 1 : 0;
}

sub _ht_strip {
    my ($path) = @_;
    # Remove only our marked block (or the file when it holds just our
    # block). Used by undo for originally-absent files and by auto-restore
    # when this apply made no backup. Never touches other backups.
    my $current = eval { _read_text_file($path) };
    if ( $@ || !defined $current ) {
        return 'missing';
    }
    if ( $current !~ /\Q$HT_BEGIN\E/ ) {
        return 'unchanged';
    }
    my @lines = split( /\n/, $current );
    my ( $bi, $ei );
    for my $i ( 0 .. $#lines ) {
        if ( !defined $bi && $lines[$i] eq $HT_BEGIN ) {
            $bi = $i;
        }
        if ( $lines[$i] eq $HT_END ) {
            $ei = $i;
        }
    }
    if ( !defined $bi || !defined $ei || $ei <= $bi ) {
        return 'unchanged';
    }
    splice @lines, $bi, $ei - $bi + 1;
    while ( @lines && $lines[-1] eq '' ) {
        pop @lines;
    }
    while ( @lines && $lines[0] eq '' ) {
        shift @lines;
    }
    if ( !@lines ) {
        unlink $path;
        return 'removed';
    }
    if ( !_write_text_file( $path, join( "\n", @lines ) . "\n", 0644 ) ) {
        return 'error';
    }
    return 'stripped';
}

sub _ht_restore_exact {
    my ( $path, $backup ) = @_;
    # Auto-restore pins the EXACT backup this apply just made: a stale
    # backup from an earlier apply is never picked up by glob. With no backup
    # (the file did not exist before this apply), strip our block instead.
    if ( defined $backup && $backup ne '' && -f $backup ) {
        if ( rename( $backup, $path ) ) {
            chmod 0644, $path;
            return 'backup';
        }
        return 'error';
    }
    return _ht_strip($path);
}

sub _ht_restore {
    my ( $path, $which ) = @_;
    # Undo fallback for files with rolling backups but no original record
    # (applies made before originals were recorded): oldest (undo) or latest. With no backup at all,
    # strip our block. Returns what happened.
    $which = 'latest' unless defined $which;
    my @all = sort glob "$path.usertools-bak-*";
    if (@all) {
        my $pick = $which eq 'oldest' ? $all[0] : $all[-1];
        if ( rename( $pick, $path ) ) {
            chmod 0644, $path;
            return 'backup';
        }
        return 'error';
    }
    return _ht_strip($path);
}

sub _ht_pair_paths {
    my ($approot) = @_;
    return ( "$approot/.htaccess", "$approot/public/.htaccess" );
}

sub _ht_root_state {
    my ( $user, $home, $approot ) = @_;
    # _ht_root_plan plus the generated block. Unsafe paths convert a
    # would-be write into a skip with a reason. Returns the plan with
    # {block} set when the root file may be written.
    my $plan = _ht_root_plan( $user, $approot );
    $plan->{block} = undef;
    if ( $plan->{write_root} ) {
        my ( $block, $err ) = _ht_root_block( $user, $home, $approot );
        if ( !defined $block ) {
            $plan->{write_root} = 0;
            $plan->{skipped}    = 1;
            $plan->{deferred}   = 0;
            $plan->{nested}     = [];
            $plan->{note}       = 'The app path has unsafe characters, so the root lock was skipped.';
        }
        else {
            $plan->{block} = $block;
        }
    }
    return $plan;
}

sub _htaccess_pair_applied {
    my ($approot) = @_;
    # The root lock in its current form: our marker plus the <If>
    # public-subtree exemption around the deny. Used for the
    # deploy-overwrite status (public file replaced, lock intact).
    my ( $root_path ) = _ht_pair_paths($approot);
    my $root = eval { _read_text_file($root_path) };
    if ( $@ || !defined $root ) {
        return 0;
    }
    return ( $root =~ /\Q$HT_BEGIN\E/ && $root =~ /<If\b/ && $root =~ /Require all denied/ ) ? 1 : 0;
}

sub _htaccess_status {
    my ($approot) = @_;
    # Deploy-overwrite status for the app list and panel: whether the
    # root lock and the public extras are currently in place.
    return {
        lock   => _htaccess_pair_applied($approot)  ? 1 : 0,
        public => _htaccess_public_applied($approot) ? 1 : 0,
    };
}

sub _htaccess_public_applied {
    my ($approot) = @_;
    # The public half of the safe pair the primary switch requires:
    # our marker plus `Require all granted`. The root file is deliberately
    # NOT required — it can only be applied after the domain points at
    # public/, otherwise it 403s the site it is meant to protect.
    my ( undef, $pub_path ) = _ht_pair_paths($approot);
    my $pub = eval { _read_text_file($pub_path) };
    if ( $@ || !defined $pub ) {
        return 0;
    }
    return ( $pub =~ /\Q$HT_BEGIN\E/ && $pub =~ /Require all granted/ ) ? 1 : 0;
}

sub _ht_root_plan {
    my ( $user, $approot ) = @_;
    # Decides whether the root deny-all may be written. Returns
    # {write_root, skipped, deferred, nested=>[...names], note}.
    # Nested domains (served from inside the app folder but not from
    # <app>/public) would inherit the root deny-all and 403 → skip the root
    # file, public file only. A domain still served from the app root
    # itself (docroot == approot) means the site is not pointed at public/
    # yet → defer the root file until the domain is pointed and apply runs
    # again ("Lock the app root").
    my ($recs) = _user_domain_info($user);
    my @nested = _nested_domains( $user, $approot, $recs );
    if (@nested) {
        return {
            write_root => 0, skipped => 1, deferred => 0,
            nested => [ map { $_->{domain} } @nested ],
            note => "These sites live inside this app's folder and would be blocked. "
              . "Move them out, or protect the app folder another way.",
        };
    }
    for my $r ( @{$recs} ) {
        my $doc = ref $r eq 'HASH' ? ( $r->{documentroot} // '' ) : '';
        if ( $doc ne '' && $doc eq $approot ) {
            return {
                write_root => 0, skipped => 0, deferred => 1, nested => [],
                note => "Point the website at the app's public folder first, "
                  . "then apply again to lock the app root.",
            };
        }
    }
    return { write_root => 1, skipped => 0, deferred => 0, nested => [], note => '' };
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_htaccess_preview / app_helper_htaccess_apply / app_helper_htaccess_undo
#-------------------------------------------------------------------------------------------------
sub app_helper_htaccess_preview {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ( $opt, $opt_err ) = _ht_options($args);
    if ( !defined $opt ) {
        $result->error( 'Invalid options: [_1].', $opt_err );
        return;
    }
    my ( $root_path, $pub_path ) = _ht_pair_paths($approot);
    my ( $rel_pub, $rel_root ) = ( 'public/.htaccess', '.htaccess' );
    my $root_cur = eval { _read_text_file($root_path) };
    if ($@) {
        $result->error( 'Cannot read root .htaccess: [_1].', "$@" );
        return;
    }
    my $pub_cur = eval { _read_text_file($pub_path) };
    if ($@) {
        $result->error( 'Cannot read public .htaccess: [_1].', "$@" );
        return;
    }
    my $plan     = _ht_root_state( $user, $home, $approot );
    my $root_new = ( $plan->{write_root} && defined $plan->{block} )
        ? _ht_merge( $root_cur, $plan->{block} ) : $root_cur;
    my $pub_new  = _ht_merge( $pub_cur, _ht_public_block( %{$opt} ) );
    $result->data(
        {
            user => $user, app => $app_param, options => $opt,
            root_skipped => $plan->{skipped} ? 1 : 0,
            root_deferred => $plan->{deferred} ? 1 : 0,
            nested_domains => $plan->{nested},
            $plan->{note} ne '' ? ( root_note => $plan->{note} ) : (),
            root => {
                file => $rel_root, exists => defined $root_cur ? 1 : 0,
                new => $root_new, diff => _ht_diff( $root_cur, $root_new ),
                warnings => _htaccess_warnings( 'root', $root_cur ),
            },
            public => {
                file => $rel_pub, exists => defined $pub_cur ? 1 : 0,
                new => $pub_new, diff => _ht_diff( $pub_cur, $pub_new ),
                warnings => _htaccess_warnings( 'public', $pub_cur ),
            },
        }
    );
    return 1;
}

sub app_helper_htaccess_apply {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ( $opt, $opt_err ) = _ht_options($args);
    if ( !defined $opt ) {
        $result->error( 'Invalid options: [_1].', $opt_err );
        return;
    }
    if ( !-d "$approot/public" ) {
        $result->error( 'Invalid app: [_1].', 'this app has no public folder yet' );
        return;
    }
    my ( $root_path, $pub_path ) = _ht_pair_paths($approot);
    my $plan = _ht_root_state( $user, $home, $approot );
    # Preserve the pre-UserTools originals first; refuse rather than
    # lose them. The root original is only needed when we write the root.
    if ( !_ht_ensure_orig( $home, $pub_path ) ) {
        $result->error('Could not preserve the public .htaccess; nothing was changed.');
        return;
    }
    if ( $plan->{write_root} && !_ht_ensure_orig( $home, $root_path ) ) {
        $result->error('Could not preserve the root .htaccess; nothing was changed.');
        return;
    }
    my $root_cur = eval { _read_text_file($root_path) };
    if ($@) {
        $result->error( 'Cannot read root .htaccess: [_1].', "$@" );
        return;
    }
    my $pub_cur = eval { _read_text_file($pub_path) };
    if ($@) {
        $result->error( 'Cannot read public .htaccess: [_1].', "$@" );
        return;
    }
    my $pub_new = _ht_merge( $pub_cur, _ht_public_block( %{$opt} ) );
    my $root_new = ( $plan->{write_root} && defined $plan->{block} )
        ? _ht_merge( $root_cur, $plan->{block} ) : undef;
    my $pub_bak = _ht_backup($pub_path);
    my $root_bak = $plan->{write_root} ? _ht_backup($root_path) : undef;
    # Apply order: the public file FIRST, then the root file (when planned).
    if ( !_write_text_file( $pub_path, $pub_new, 0644 ) ) {
        $result->error('Could not write the public .htaccess file.');
        return;
    }
    if ( $plan->{write_root} && !_write_text_file( $root_path, $root_new, 0644 ) ) {
        _ht_restore_exact( $pub_path, $pub_bak );
        $result->error('Could not write the root .htaccess file; the public file was restored.');
        return;
    }
    # Then run the .env check automatically.
    my $probe   = _env_probe_app( $user, $approot );
    my $checked = ref $probe->{checked} eq 'ARRAY' ? $probe->{checked} : [];
    # Homepage guard over every affected domain: restore the files
    # THIS apply wrote when any of them serves a real 403/500-598.
    my $guard = _guard_homepages( $user, $approot );
    my ( $restored, $reason ) = ( 0, '' );
    if ( $guard->{failed} ) {
        _ht_restore_exact( $pub_path, $pub_bak );
        if ( $plan->{write_root} ) {
            _ht_restore_exact( $root_path, $root_bak );
        }
        $restored = 1;
        $reason   = "Homepage https://$guard->{domain}/ returned $guard->{status} after apply, "
          . "so the written files were restored. Check the option checkboxes and try again.";
    }
    $result->data(
        {
            user => $user, app => $app_param, options => $opt,
            root_skipped => $plan->{skipped} ? 1 : 0,
            root_deferred => $plan->{deferred} ? 1 : 0,
            nested_domains => $plan->{nested},
            $plan->{note} ne '' ? ( root_note => $plan->{note} ) : (),
            backups  => { root => $root_bak, public => $pub_bak },
            checked  => $checked,
            homepage => {
                domain => $guard->{first_domain}, status => $guard->{first_status} // 0,
                checked => $guard->{checked}, failed => $guard->{failed} ? 1 : 0,
                warning => $guard->{warning},
            },
            restored => $restored,
            $restored ? ( reason => $reason ) : (),
            $guard->{warning} ne '' && !$restored ? ( guard_warning => $guard->{warning} ) : (),
        }
    );
    _activity_log( $home, 'app_helper', 'apply htaccess',
        { app => $app_param },
        { fn => 'app_helper_htaccess_undo', args => { app => $app_param } } );
    return 1;
}

sub app_helper_htaccess_undo {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ( $root_path, $pub_path ) = _ht_pair_paths($approot);
    my $root_rel = _ht_home_rel( $home, $root_path );
    my $pub_rel  = _ht_home_rel( $home, $pub_path );
    my $files    = _read_ht_orig_journal($home);
    my $root_restored = _ht_undo_one( $files, $root_rel, $root_path );
    my $pub_restored  = _ht_undo_one( $files, $pub_rel, $pub_path );
    _write_ht_orig_journal( $home, $files );
    if ( ( $root_restored eq 'missing' || $root_restored eq 'unchanged' )
        && ( $pub_restored eq 'missing' || $pub_restored eq 'unchanged' ) )
    {
        $result->error('Nothing to undo: no originals, backups or UserTools blocks found.');
        return;
    }
    $result->data(
        { user => $user, app => $app_param, root => $root_restored, public => $pub_restored } );
    _activity_log( $home, 'app_helper', 'undo htaccess',
        { app => $app_param }, undef );
    return 1;
}

sub _ht_undo_one {
    my ( $files_hr, $rel, $path ) = @_;
    # Undo one file against its original record. Files recorded
    # {absent} lose our block (or the whole file when it holds only our
    # block); files with a saved original get it back byte-for-byte. Files
    # with no record fall back to the oldest rolling backup (applies
    # made before originals were recorded). Every restored state then passes _ht_undo_clean: the
    # account-creation hook can make a UserTools lock file the recorded
    # "original", so restoring it verbatim would re-arm the root lock
    # forever. $_[0] is updated in place: the record is dropped unless the
    # restore errored.
    if ( !defined $rel || $rel eq '' ) {
        return 'error';
    }
    my $entry = $files_hr->{$rel};
    if ( !defined $entry ) {
        my $st = _ht_restore( $path, 'oldest' );
        return _ht_undo_clean( $path, $st );
    }
    if ( ref $entry eq 'HASH' && $entry->{absent} ) {
        my $st = _ht_strip($path);
        delete $files_hr->{$rel} unless $st eq 'error';
        return $st;
    }
    my $orig = ref $entry eq 'HASH' ? $entry->{orig} : undef;
    if ( defined $orig && $orig ne '' && -f $orig ) {
        if ( rename( $orig, $path ) ) {
            chmod 0644, $path;
            delete $files_hr->{$rel};
            return _ht_undo_clean( $path, 'original' );
        }
        return 'error';
    }
    my $st = _ht_restore( $path, 'oldest' );
    delete $files_hr->{$rel} unless $st eq 'error';
    return _ht_undo_clean( $path, $st );
}

sub _ht_remove_block {
    my ($content) = @_;
    # Drop our marked block(s) and keep every other byte: the
    # split(-1)/join round-trip reproduces the input byte-for-byte, so only
    # the marker lines disappear. Every complete block is removed — the
    # point is that no "# BEGIN UserTools … # END UserTools" section can
    # survive the sweep. Returns the content without our blocks, or undef
    # when there is no complete block to remove (no markers, or a marker
    # the user edited beyond recognition — never guessed at).
    return undef unless defined $content && index( $content, $HT_BEGIN ) >= 0;
    my @lines = split /\n/, $content, -1;
    my @keep;
    my $in_block = 0;
    my $found    = 0;
    for my $line (@lines) {
        if ( $line eq $HT_BEGIN ) {
            $in_block = 1;
            $found    = 1;
            next;
        }
        if ( $in_block && $line eq $HT_END ) {
            $in_block = 0;
            next;
        }
        push @keep, $line unless $in_block;
    }
    return undef unless $found && !$in_block;
    return join "\n", @keep;
}

sub _ht_undo_clean {
    my ( $path, $st ) = @_;
    # Post-restore sweep against the LIVE file. An original (or backup)
    # captured from a hook-written file carries our marked block — the root
    # lock for the root file — so undo strips it from root and public alike
    # and keeps every other byte. An empty remainder means the file existed
    # only because UserTools wrote it, so the file goes; files without our
    # markers keep the restore's own label untouched (byte-identical
    # restore of user content).
    return $st if $st eq 'error';
    my $content = eval { _read_text_file($path) };
    return $st if $@ || !defined $content;
    my $stripped = _ht_remove_block($content);
    return $st unless defined $stripped;
    if ( $stripped eq '' ) {
        return unlink($path) ? 'removed' : 'error';
    }
    return _write_text_file( $path, $stripped, 0644 ) ? 'stripped' : 'error';
}

# ---------------------------------------------------------------------------
# Primary-domain switch (user side). The privileged step goes through the
# Admin module; here we check the preconditions first: the app must live
# directly in public_html/, public/index.php must exist, and the PUBLIC
# .htaccess must carry our marker (the root deny-all can only be
# applied after the domain points at public/, otherwise it 403s the site).
# Otherwise the page shows "Ask my host" with the copy-ready host command.
# ---------------------------------------------------------------------------

sub _read_user_policy {
    my ($path) = @_;
    $path = defined $TEST_POLICY_FILE ? $TEST_POLICY_FILE : '/etc/usertools.conf'
      unless defined $path;
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

sub _primary_host_command {
    my ($user) = @_;
    return "whmapi1 set_primary_domain_docroot username=$user docroot=public_html/public";
}

sub _primary_readiness {
    my ( $home, $approot ) = @_;
    # Returns {eligible, reason?, index_ok, htaccess_ok, rel}.
    my $rel = $approot eq $home ? '' : substr( $approot, length("$home/") );
    if ( $rel ne 'public_html' ) {
        return {
            eligible => 0, rel => $rel, index_ok => 0, htaccess_ok => 0,
            reason => 'The main-domain switch is for apps that live directly in public_html/.',
        };
    }
    my $index_ok = -f "$approot/public/index.php" ? 1 : 0;
    if ( !$index_ok ) {
        return {
            eligible => 0, rel => $rel, index_ok => 0, htaccess_ok => 0,
            reason => 'public_html/public/index.php is missing.',
        };
    }
    my $htaccess_ok = _htaccess_public_applied($approot);
    my $lock        = _htaccess_pair_applied($approot) ? 1 : 0;
    if ( !$htaccess_ok && !$lock ) {
        return {
            eligible => 0, rel => $rel, index_ok => 1, htaccess_ok => 0, lock => 0,
            reason => 'Apply the public .htaccess first (point the domain, then lock the app root).',
        };
    }
    return { eligible => 1, rel => $rel, index_ok => 1, htaccess_ok => 1, lock => $lock };
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_primary_check / app_helper_primary_set
#-------------------------------------------------------------------------------------------------
sub app_helper_primary_check {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my $ready  = _primary_readiness( $home, $approot );
    my $policy = _read_user_policy();
    my $allowed = ( ( $policy->{allow_user_app_docroot} // '' ) eq '1' ) ? 1 : 0;
    my ( $recs, $main_domain ) = _user_domain_info($user);
    my $current;
    if ( defined $main_domain ) {
        for my $r ( @{$recs} ) {
            if ( lc( $r->{domain} ) eq lc($main_domain) ) {
                $current = $r->{documentroot};
                last;
            }
        }
    }
    my $eligible = $ready->{eligible} ? 1 : 0;
    my $reason   = $ready->{reason};
    if ( !$eligible && $ready->{rel} eq 'public_html' && defined $current ) {
        # The main domain already serves this app's public/ folder, so
        # the only direction left is BACK to public_html (enable=0), which
        # app_helper_primary_set allows without the public/root pair — the panel must
        # offer that revert instead of a dead end.
        ( my $cur = $current ) =~ s{/+\z}{};
        my $pub = "$home/public_html/public";
        if ( $cur eq $pub || index( $cur, "$pub/" ) == 0 ) {
            $eligible = 1;
            $reason   = undef;
        }
    }
    $result->data(
        {
            user => $user, app => $app_param,
            eligible => $eligible,
            $eligible ? () : ( reason => $reason ),
            index_ok => $ready->{index_ok} ? 1 : 0,
            htaccess_ok => $ready->{htaccess_ok} ? 1 : 0,
            lock => $ready->{lock} ? 1 : 0,
            current_docroot => $current,
            policy_allowed => $allowed,
            host_command => _primary_host_command($user),
        }
    );
    return 1;
}

sub app_helper_primary_set {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($enable_param) = $args->get('enable');
    my $on;
    if ( !ref $enable_param && defined $enable_param && ( $enable_param eq '1' || $enable_param eq '0' ) ) {
        $on = $enable_param eq '1' ? 1 : 0;
    }
    elsif ( ref $enable_param && eval { $enable_param->isa('JSON::PP::Boolean') } ) {
        $on = $enable_param ? 1 : 0;
    }
    else {
        $result->error( 'Invalid switch: [_1].', 'enable must be 0 or 1' );
        return;
    }
    my $ready = _primary_readiness( $home, $approot );
    if ( !$ready->{eligible} && ( $on || $ready->{rel} ne 'public_html' ) ) {
        # Switching BACK needs only the app layout — the public/root pair (and
        # the index check) protects pointing the domain AT the app, while
        # leaving it never 403s the site; a full undo strips the pair, so
        # gating enable=0 on it would be a new dead end. The live root lock
        # below stays the real gate for enable=0, and lock detection reads
        # the live file only.
        ( my $reason = $ready->{reason} // '' ) =~ s/\.\z//;
        $result->error( 'Main-domain switch refused: [_1].', $reason );
        return;
    }
    if ( !$on && $ready->{lock} ) {
        # Switching back to public_html while the root lock is on would 403
        # the site: the lock must be undone first ($ready->{lock} comes
        # from the live root file, never from journal state).
        $result->error( 'Main-domain switch refused: [_1].',
            'remove the root lock first (undo the .htaccess lock), then switch back' );
        return;
    }
    my $admin = _adminbin_reply( 'AppDocroot', 'SET_APP_DOCROOT', { enable => $on } );
    if ( my $err = $admin->{error} ) {
        if ( _is_suspended_error($err) ) {
            $result->error('Your account is suspended; main-domain changes are unavailable.');
            return;
        }
        ( my $plain = $err ) =~ s/\.\z//;
        $result->error( 'Main-domain change error: [_1].', $plain );
        return;
    }
    $result->data($admin);
    _activity_log( $home, 'app_helper', 'set primary domain',
        { app => $app_param, enable => $on },
        { fn => 'app_helper_primary_set',
          args => { app => $app_param, enable => $on ? 0 : 1 } } );
    return 1;
}

# ---------------------------------------------------------------------------
# App Helper (tool E): deploy & maintain. Long runs (composer,
# npm) go through detached recipe jobs with progress/cancel/capped logs;
# quick fixed-argv actions (maintenance, queue, key, config cache) run
# synchronously; reads (logs, readiness, cron state, quota) are synchronous.
# Every recipe is a fixed argv list (no shell, no free-text arguments) and
# `app` is re-validated on every call. Binaries come only from the
# documented trees and pass ownership + allowlist checks.
# ---------------------------------------------------------------------------

our $RECIPE_WORKER_PATH = '/usr/local/cpanel/3rdparty/usertools/bin/recipe_worker.py';
our $DEPLOY_STEP_TIMEOUT = 3600;
our $DEPLOY_LOG_CAP      = 262144;
our $DEPLOY_LOG_TAIL     = 32768;
our $DOTENV_MAX_BYTES    = 65536;
our $LOG_VIEW_BYTES      = 65536;
our $LOG_VIEW_LINES      = 200;
our $DEPLOY_CANCEL_GRACE = 10;

sub _policy_max_job_seconds {
    # Overall recipe budget from the public policy (default 3600, clamped
    # 60..86400 like the WHM validation). World-readable by design.
    my $file = defined $TEST_POLICY_FILE ? $TEST_POLICY_FILE : '/etc/usertools.conf';
    if ( open my $fh, '<', $file ) {
        while ( my $line = <$fh> ) {
            if ( $line =~ /^\s*max_job_seconds\s*=\s*(\d+)\s*(?:[;#].*)?$/ ) {
                close $fh;
                my $v = $1;
                if ( $v >= 60 && $v <= 86400 ) {
                    return $v + 0;
                }
                return 3600;
            }
        }
        close $fh;
    }
    return 3600;
}

sub _proc_is_recipe_worker {
    my ($pid) = @_;
    if ( $pid !~ /^\d+$/ ) {
        return 0;
    }
    my $fh;
    if ( !open $fh, '<', "/proc/$pid/cmdline" ) {
        return 0;
    }
    my $cmd = <$fh>;
    close $fh;
    return 0 unless defined $cmd;
    $cmd =~ s/\0/ /g;
    return $cmd =~ /recipe_worker\.py/ ? 1 : 0;
}

sub _find_composer {
    # Discovery order — the WHM page (find_composer in the settings CGI)
    # mirrors this list and must stay in sync, so the page shows exactly
    # which binary would run:
    #   1. composer_path= in /etc/usertools.conf (root-only WHM setting),
    #   2. /usr/local/bin/composer (the getcomposer.org global install),
    #   3. /opt/cpanel/composer/bin/composer (only if something put one
    #      there; no repo on a stock 11.138 AlmaLinux 9 provides it).
    # Every candidate must be a regular executable that is root-owned and
    # not writable by group or others, or it is refused — and an existing
    # but UNSAFE candidate stops the search (the admin must fix it; it is
    # never silently skipped for whatever comes next). $TEST_COMPOSER fakes
    # the binary in tests (replaces the whole list).
    # CloudLinux/CageFS: this module already runs as the user inside
    # the cage, so `-x` above is the visibility check — but a path that
    # exists on the host yet is not mounted into the cage must be reported
    # as not visible (not as found), with the conf.d remedy, so the page
    # hides the Composer button instead of failing at runtime.
    my @cands;
    if ( defined $TEST_COMPOSER ) {
        @cands = ($TEST_COMPOSER);
    }
    else {
        my $file = defined $TEST_POLICY_FILE ? $TEST_POLICY_FILE : '/etc/usertools.conf';
        if ( open my $fh, '<', $file ) {
            while ( my $line = <$fh> ) {
                next unless $line =~ /^\s*composer_path\s*=/;
                my ( undef, $v ) = split /=/, $line, 2;
                $v = '' unless defined $v;
                $v =~ s/\s*[;#].*$//;
                $v =~ s/^\s+|\s+$//g;
                # Absolute path shape only (the WHM page validates on
                # write; a hand-edited conf must not smuggle whitespace or
                # control bytes into the argv list).
                push @cands, $v if $v =~ m{^/[A-Za-z0-9][A-Za-z0-9._+/-]*$};
                last;
            }
            close $fh;
        }
        push @cands, @COMPOSER_DEFAULT_PATHS;
    }
    for my $bin (@cands) {
        next unless defined $bin && $bin ne '';
        my @st = lstat $bin;
        next unless @st && -f _ && -x _;
        if ( $st[4] != 0 || ( $st[2] & 0022 ) != 0 ) {
            return ( undef,
                "composer at $bin has unsafe ownership or permissions (must be root-owned, no group/other write)"
            );
        }
        if ( _cagefs_active() && !_path_visible_in_cage($bin) ) {
            return ( undef,
                "composer at $bin found, but not visible to caged users (add a CageFS conf.d INI entry for this path, then run cagefsctl --force-update)"
            );
        }
        return ( $bin, undef );
    }
    return ( undef,
        'no composer binary found (set composer_path in /etc/usertools.conf or install composer to /usr/local/bin/composer)'
    );
}

sub _cagefs_active {
    # CageFS present and enabled: the mount-points file exists. Test seam
    # $TEST_CAGEFS_MP fakes the path (undef = production path).
    my $mp = defined $TEST_CAGEFS_MP ? $TEST_CAGEFS_MP : '/etc/cagefs/cagefs.mp';
    return -f $mp ? 1 : 0;
}

sub _cagefs_conf_d {
    return defined $TEST_CAGEFS_CONF_D ? $TEST_CAGEFS_CONF_D : '/etc/cagefs/conf.d';
}

sub _path_visible_in_cage {
    # True when CageFS is off, or when $path is literally listed in any
    # conf.d *.cfg entry (the INI `paths=` list) or in cagefs.mp. The UAPI
    # module runs as the user inside the cage, so this is defence in depth
    # on top of the `-x` check above: a host-visible path that CageFS does
    # not mount must not be reported as found.
    # Fail OPEN: /etc/cagefs/conf.d is commonly 0711 (traversable but not
    # listable), so the user cannot enumerate it — and an unprovable
    # absence must never veto a path whose `-x` check already passed.
    # Only a readable config set that omits the path counts as not visible.
    my ($path) = @_;
    return 1 unless _cagefs_active();
    my $dir = _cagefs_conf_d();
    my ( $listed, $read_any ) = ( 0, 0 );
    if ( opendir my $dh, $dir ) {
        $listed = 1;
        my @files = grep { /\.cfg$/ } readdir $dh;
        closedir $dh;
        for my $f (@files) {
            if ( open my $fh, '<', "$dir/$f" ) {
                $read_any = 1;
                local $/;
                my $content = <$fh>;
                close $fh;
                if ( defined $content && index( $content, $path ) >= 0 ) {
                    return 1;
                }
            }
        }
    }
    return 1 unless $listed;    # cannot enumerate conf.d: absence unprovable
    my $mp = defined $TEST_CAGEFS_MP ? $TEST_CAGEFS_MP : '/etc/cagefs/cagefs.mp';
    if ( open my $fh, '<', $mp ) {
        $read_any = 1;
        local $/;
        my $content = <$fh>;
        close $fh;
        if ( defined $content && index( $content, $path ) >= 0 ) {
            return 1;
        }
    }
    return 1 unless $read_any;    # enumerated nothing readable: unprovable
    return 0;
}

sub _node_wanted_major {
    my ($approot) = @_;
    # Parse package.json engines (string or {node}): a simple >=N, ^N, N.x
    # or bare N yields the wanted major; anything else means no preference.
    my $file = "$approot/package.json";
    my @st = lstat $file;
    if ( !@st || -l _ || !-f _ || $st[7] > 262144 ) {
        return undef;
    }
    if ( open my $fh, '<', $file ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' ) {
            my $eng = $data->{engines};
            my $want;
            if ( !ref $eng && defined $eng ) {
                $want = $eng;
            }
            elsif ( ref $eng eq 'HASH' && defined $eng->{node} && !ref $eng->{node} ) {
                $want = $eng->{node};
            }
            if ( defined $want ) {
                $want =~ s/^\s+|\s+$//g;
                if ( $want =~ /^(?:>=|\^|~)?(\d+)(?:\.[x*])?$/ ) {
                    return "$1";
                }
            }
        }
    }
    return undef;
}

sub _select_node_for_app {
    my ( $approot, $cpanel_base, $alt_base ) = @_;
    # Newest installed Node with the engines major, else newest available
    # with a warning. Returns (bin, source, warning).
    # CloudLinux layout is root/usr/bin (alt-nodejsNN/root/usr/bin/node).
    my @families;
    push @families, [ defined $cpanel_base ? $cpanel_base : '/opt/cpanel', qr/^ea-nodejs(\d+)$/, 'bin/node' ];
    push @families, [ defined $alt_base ? $alt_base : '/opt/alt', qr/^alt-nodejs(\d+)$/, 'root/usr/bin/node' ];
    my @found;
    for my $fam (@families) {
        my ( $base, $re, $rel ) = @{$fam};
        my $dh;
        if ( !opendir( $dh, $base ) ) {
            next;
        }
        my @cands = map { /$re/ ? [ $1, $_ ] : () } readdir $dh;
        closedir $dh;
        for my $c (@cands) {
            my $bin = "$base/$c->[1]/$rel";
            if ( -f $bin && -x $bin ) {
                push @found, { major => $c->[0], bin => $bin };
            }
        }
    }
    if ( !@found ) {
        return ( undef, undef, 'no Node.js available' );
    }
    my $wanted = _node_wanted_major($approot);
    if ( defined $wanted ) {
        my @match = grep { $_->{major} == $wanted } @found;
        if (@match) {
            my ($best) = sort { $b->{major} <=> $a->{major} } @match;
            return ( $best->{bin}, 'node', undef );
        }
        my ($best) = sort { $b->{major} <=> $a->{major} } @found;
        return ( $best->{bin}, 'node', "engines wants Node $wanted, using newest available" );
    }
    my ($best) = sort { $b->{major} <=> $a->{major} } @found;
    return ( $best->{bin}, 'node', undef );
}

sub _quota_info {
    my ($user) = @_;
    # Disk + inode quota for the npm warning (UAPI Quota::get_quota_info;
    # fields per the v11.138 spec). Best effort: undef when unavailable.
    my $res = eval { Cpanel::API::execute( 'Quota', 'get_quota_info', {} ) };
    if ( $@ || !defined $res || !ref $res ) {
        return undef;
    }
    my ( $data, $status );
    if ( eval { $res->can('status') } ) {
        $status = eval { $res->status() };
        my $d = eval { $res->data() };
        $data = $d if ref $d eq 'HASH';
    }
    elsif ( ref $res eq 'HASH' ) {
        $status = $res->{status};
        $data   = $res->{data} if ref $res->{data} eq 'HASH';
        if ( !defined $data && ref $res->{result} eq 'HASH' && ref $res->{result}{data} eq 'HASH' ) {
            $data = $res->{result}{data};
        }
    }
    if ( !defined $status || $status != 1 || ref $data ne 'HASH' ) {
        return undef;
    }
    my %out;
    for my $k (qw(megabytes_used megabyte_limit inodes_used inode_limit under_quota_overall)) {
        if ( defined $data->{$k} && $data->{$k} =~ /^-?[\d.]+$/ ) {
            $out{$k} = $data->{$k} + 0;
        }
    }
    if ( !exists $out{megabytes_used} && !exists $out{inodes_used} ) {
        return undef;
    }
    return \%out;
}

sub _deploy_base_env {
    my ( $home, %extra ) = @_;
    # Existing allowlist plus the CageFS-safe cache homes (never /tmp).
    # Node 22 writes its compile cache under /tmp by default and build
    # tools honour TMPDIR — both point inside the account (CageFS gives each
    # user a private /tmp, so shared temp would break or leak). The two
    # directories are created 0700 in _deploy_start_job; npm/composer create
    # their own COMPOSER_HOME/npm_config_cache on demand as the user.
    return (
        PATH => '/usr/local/bin:/usr/bin:/bin', HOME => $home, LANG => 'C.UTF-8',
        COMPOSER_HOME   => "$home/.cache/usertools/composer",
        npm_config_cache => "$home/.cache/usertools/npm",
        NODE_COMPILE_CACHE => "$home/.cache/usertools/node-compile-cache",
        TMPDIR => "$home/.cache/usertools/tmp",
        %extra,
    );
}

sub _spawn_recipe {
    my ( $home, $job, $recipe_file ) = @_;
    # Double-fork + setsid detach mirroring _spawn_engine. Returns the
    # worker pid or (undef, reason).
    my ( $rd, $wr );
    if ( !pipe( $rd, $wr ) ) {
        return ( undef, "cannot create pipe: $!" );
    }
    my $kid = fork();
    if ( !defined $kid ) {
        close $rd;
        close $wr;
        return ( undef, "cannot fork: $!" );
    }
    if ( $kid == 0 ) {
        close $rd;
        setsid();
        my $py  = $TEST_ENGINE_BIN // $ENGINE_PYTHON;
        my $bin = defined $TEST_RECIPE_WORKER ? $TEST_RECIPE_WORKER : $RECIPE_WORKER_PATH;
        my $budget = _policy_max_job_seconds();
        my @cmd = (
            $py, $bin, '--recipe', $recipe_file,
            '--progress', $job->{progress}, '--result', $job->{result},
            '--log', $job->{log}, '--log-cap', "$DEPLOY_LOG_CAP",
            '--budget', "$budget",
        );
        my $grand = fork();
        if ( !defined $grand ) {
            POSIX::_exit(127);
        }
        if ( $grand == 0 ) {
            close $wr;
            open STDIN,  '<', '/dev/null' or POSIX::_exit(127);
            my $log = $job->{log};
            open STDOUT, '>>', $log or POSIX::_exit(127);
            open STDERR, '>', $job->{stderr} or POSIX::_exit(127);
            exec { $cmd[0] } @cmd or POSIX::_exit(127);
        }
        print $wr "$grand\n";
        close $wr;
        POSIX::_exit(0);
    }
    close $wr;
    my $line = <$rd>;
    close $rd;
    waitpid( $kid, 0 );
    $line = '' unless defined $line;
    chomp($line);
    if ( $line =~ /^\d+$/ ) {
        return $line;
    }
    return ( undef, 'worker did not start' );
}

sub _deploy_find_live {
    my ( $home, $app_rel ) = @_;
    # Newest live deploy job, optionally for one app: verified worker pid
    # owned by the caller with no result file yet.
    my $dir = _jobs_dir($home);
    my $dh;
    if ( !opendir( $dh, $dir ) ) {
        return undef;
    }
    my @metas = grep { /\.job\.json$/ } readdir $dh;
    closedir $dh;
    my @with_age =
      map { { name => $_, mtime => ( ( stat("$dir/$_") )[9] // 0 ) } } @metas;
    for my $m ( sort { $b->{mtime} <=> $a->{mtime} } @with_age ) {
        my $meta = _read_json_file("$dir/$m->{name}");
        next unless ref $meta eq 'HASH' && $meta->{pid} && $meta->{id};
        next unless ( $meta->{tool} // '' ) eq 'deploy';
        if ( defined $app_rel && ( $meta->{app} // '' ) ne $app_rel ) {
            next;
        }
        next unless kill( 0, $meta->{pid} );
        next unless _proc_owner_ok( $meta->{pid}, $> );
        next unless _proc_is_recipe_worker( $meta->{pid} );
        my $job = _job_paths( $home, $meta->{id} );
        next unless defined $job;
        next if -f $job->{result};
        next if -f $job->{cancelled};
        return $meta;
    }
    return undef;
}

sub _strip_ansi {
    # Composer (and npm/artisan) paint job logs with ANSI escapes
    # ("[39m[90m." in the stored log). The composer argv now asks for no
    # colour (--no-ansi --no-progress), and every captured log is stripped
    # before storing or returning it: CSI sequences plus OSC hyperlinks.
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/\x1b\[[0-9;?]*[ -\/]*[@-~]//g;
    $text =~ s/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)//g;
    $text =~ s/\x1b[()][0-9A-B]//g;
    return $text;
}

sub _deploy_log_tail {
    my ( $job, $cap ) = @_;
    $cap = $DEPLOY_LOG_TAIL unless defined $cap;
    if ( open my $fh, '<', $job->{log} ) {
        my $size = ( stat($fh) )[7] // 0;
        if ( $size > $cap ) {
            seek( $fh, $size - $cap, 0 );
            <$fh>;
        }
        local $/;
        my $tail = <$fh>;
        close $fh;
        return defined $tail ? _strip_ansi($tail) : '';
    }
    return '';
}

sub _deploy_recipe_composer {
    my ( $home, $approot, $php_bin, $composer ) = @_;
    # Hardened servers ship EA-PHP with allow_url_fopen=Off, which makes
    # Composer refuse to run (it fetches packages over HTTP). Flip it for
    # THIS invocation only — `-d key=value` on the PHP command line, in the
    # argv list (no shell) — so the setting applies to this one process and
    # nothing else. No php.ini is ever read for a write, anywhere.
    # When the admin explicitly sets composer_lift_disable_functions=1
    # (default 0, never set by the installer), this one Composer process
    # also runs with an empty disable_functions (re-enabling proc_open for
    # that process only). Anything else keeps the host hardening intact.
    my $lift = 0;
    my $policy = eval { _read_user_policy() };
    if ( ref $policy eq 'HASH' && ( $policy->{composer_lift_disable_functions} // '' ) eq '1' ) {
        $lift = 1;
    }
    my @argv = ( $php_bin, '-d', 'allow_url_fopen=1' );
    push @argv, ( '-d', 'disable_functions=' ) if $lift;
    push @argv, (
        $composer, 'install',
        '--no-dev', '--optimize-autoloader', '--no-interaction',
        '--no-ansi', '--no-progress',
    );
    return {
        steps => [
            {
                name => 'composer install', cwd => $approot, timeout => $DEPLOY_STEP_TIMEOUT,
                argv => \@argv,
                env => { _deploy_base_env($home) },
            },
        ],
    };
}

sub _php_disable_functions {
    # Read disable_functions from the SELECTED PHP binary as the user (the
    # UAPI module already runs as the user). Returns the raw ini string or
    # undef when it cannot be determined (fail open: callers treat undef as
    # "unknown", not as disabled).
    my ( $php_bin, $cwd ) = @_;
    return undef unless defined $php_bin && _php_bin_allowed($php_bin);
    $cwd = '/' unless defined $cwd && -d $cwd;
    my $res = _spawn_sync(
        [ $php_bin, '-r', 'echo ini_get("disable_functions");' ], $cwd,
        { PATH => '/usr/local/bin:/usr/bin:/bin', HOME => $ENV{HOME} // '/tmp', LANG => 'C.UTF-8' },
        10, 8192,
    );
    return undef unless ref $res eq 'HASH';
    return undef if $res->{timed_out} || ( $res->{exit} // 1 ) != 0;
    my $out = $res->{output} // '';
    $out =~ s/^\s+|\s+$//g;
    return $out;
}

sub _proc_open_disabled {
    my ( $php_bin, $cwd ) = @_;
    my $list = _php_disable_functions( $php_bin, $cwd );
    return 0 unless defined $list && $list ne '';
    return $list =~ /(?:^|,)\s*proc_open\s*(?:,|$)/i ? 1 : 0;
}

sub _app_required_extensions {
    # Extensions the app needs: every `ext-*` key in composer.json require /
    # require-dev plus every `ext-*` key in composer.lock's platform and
    # platform-overrides sections. Returns sorted unique short names
    # (without the `ext-` prefix, lowercased).
    my ($approot) = @_;
    my %need;
    if ( open my $fh, '<', "$approot/composer.json" ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' ) {
            for my $section (qw(require require-dev)) {
                my $req = $data->{$section};
                next unless ref $req eq 'HASH';
                for my $k ( keys %{$req} ) {
                    if ( $k =~ /^ext-(.+)$/i ) {
                        $need{ lc $1 } = 1;
                    }
                }
            }
        }
    }
    if ( open my $fh, '<', "$approot/composer.lock" ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' ) {
            for my $section (qw(platform platform-overrides)) {
                my $plat = $data->{$section};
                next unless ref $plat eq 'HASH';
                for my $k ( keys %{$plat} ) {
                    if ( $k =~ /^ext-(.+)$/i ) {
                        $need{ lc $1 } = 1;
                    }
                }
            }
        }
    }
    return [ sort keys %need ];
}

sub _php_loaded_extensions {
    # Lowercased `php -m` module list for $php_bin, or undef when unknown.
    my ( $php_bin, $cwd ) = @_;
    return undef unless defined $php_bin && _php_bin_allowed($php_bin);
    $cwd = '/' unless defined $cwd && -d $cwd;
    my $res = _spawn_sync(
        [ $php_bin, '-m' ], $cwd,
        { PATH => '/usr/local/bin:/usr/bin:/bin', HOME => $ENV{HOME} // '/tmp', LANG => 'C.UTF-8' },
        10, 32768,
    );
    return undef unless ref $res eq 'HASH';
    return undef if $res->{timed_out} || ( $res->{exit} // 1 ) != 0;
    my %have;
    for my $line ( split /\n/, ( $res->{output} // '' ) ) {
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^\[/;
        $have{ lc $line } = 1;
    }
    return \%have;
}

sub _php_missing_extensions {
    # Required short names (from _app_required_extensions) minus what the
    # selected PHP reports via `php -m`. Undef when the requirement list is
    # empty or the loaded list is unknown (callers show nothing then).
    my ( $php_bin, $cwd, $required_ar ) = @_;
    $required_ar = [] unless ref $required_ar eq 'ARRAY';
    return undef unless @{$required_ar};
    my $have = _php_loaded_extensions( $php_bin, $cwd );
    return undef unless ref $have eq 'HASH';
    my @missing = grep { !$have->{$_} } @{$required_ar};
    return \@missing;
}

sub _deploy_recipe_npm {
    my ( $home, $approot, $npm_bin, $keep_nm ) = @_;
    # Stock skeletons ship no package-lock.json and `npm ci` refuses
    # without one — pick per app: lockfile present means `ci`, otherwise
    # `install --no-audit --no-fund` (which CREATES the lockfile; the start
    # response tells the user to commit it).
    my $has_lock = -f "$approot/package-lock.json" ? 1 : 0;
    my @install_argv = $has_lock
        ? ( $npm_bin, 'ci' )
        : ( $npm_bin, 'install', '--no-audit', '--no-fund' );
    # npm itself runs by absolute path, but the app's lifecycle scripts
    # (vite's `#!/usr/bin/env node`) resolve `node` through PATH — prepend
    # the SELECTED Node's bin dir so env-node finds the right binary.
    ( my $node_dir = $npm_bin ) =~ s{/bin/npm$}{};
    my $node_bindir = "$node_dir/bin";
    my %npm_env = _deploy_base_env( $home, PATH => "$node_bindir:/usr/local/bin:/usr/bin:/bin" );
    my $rm_step = {
        name => 'remove node_modules', cwd => $approot, timeout => 600,
        argv => [ '/bin/rm', '-rf', 'node_modules' ],
        env  => { %npm_env },
    };
    my @steps = (
        {
            name => $has_lock ? 'npm ci' : 'npm install', cwd => $approot,
            timeout => $DEPLOY_STEP_TIMEOUT,
            argv => \@install_argv,
            env  => { %npm_env },
        },
        {
            name => 'npm run build', cwd => $approot, timeout => $DEPLOY_STEP_TIMEOUT,
            argv => [ $npm_bin, 'run', 'build' ],
            env  => { %npm_env },
        },
    );
    my %recipe = ( steps => \@steps, installer => $has_lock ? 'ci' : 'install' );
    if ( !$keep_nm ) {
        # Success path: rm runs as the last step. Failure path (the worker
        # stops at the first failing step): on_failure below.
        push @steps, { %{$rm_step} };
        $recipe{on_failure} = { %{$rm_step}, name => 'remove node_modules (failure cleanup)' };
    }
    return \%recipe;
}

sub _ensure_cache_dirs {
    my ($home) = @_;
    # TMPDIR + NODE_COMPILE_CACHE must exist before the first step runs
    # (build tools do not create TMPDIR for us). 0700: caches can hold
    # tokens and tarballs; never group/world-readable. Returns undef on
    # success, else an error string (unit-tested directly).
    for my $d ( "$home/.cache/usertools/tmp", "$home/.cache/usertools/node-compile-cache" ) {
        eval { make_path( $d, { mode => 0700 } ) };
        return "$@" if $@;
        chmod 0700, $d;
    }
    return undef;
}

sub _deploy_start_job {
    my ( $result, $user, $home, $rel, $approot, $recipe_name, $recipe_hr, $extra_hr ) = @_;
    my $jobs_dir = _jobs_dir($home);
    eval { make_path( $jobs_dir, { mode => 0700 } ) };
    if ($@) {
        $result->error( 'Cannot create job directory: [_1].', "$@" );
        return;
    }
    if ( my $err = _ensure_cache_dirs($home) ) {
        $result->error( 'Cannot create cache directory: [_1].', $err );
        return;
    }
    my $job_id = _job_id_new('deploy');
    my $job    = _job_paths( $home, $job_id );
    my $rfh;
    if ( !open $rfh, '>', $job->{recipe} ) {
        $result->error( 'Cannot record job: [_1].', "$!" );
        return;
    }
    print $rfh JSON::PP->new()->canonical(1)->encode($recipe_hr);
    close $rfh;
    chmod 0600, $job->{recipe};
    my ( $pid, $spawn_err ) = _spawn_recipe( $home, $job, $job->{recipe} );
    if ( !defined $pid ) {
        unlink $job->{recipe};
        $result->error( 'Cannot start background job: [_1].', $spawn_err );
        return;
    }
    usleep(200000);
    my $early = _read_json_file( $job->{result} );
    my $alive = kill( 0, $pid ) ? 1 : 0;
    if ( !$alive && !$early ) {
        unlink $job->{recipe};
        $result->raw_error('The background job failed to start. Retry, or contact your host.');
        return;
    }
    my $meta = {
        id => $job_id, pid => $pid + 0, tool => 'deploy',
        app => $rel, recipe => $recipe_name, started => time(),
        %{ $extra_hr // {} },
    };
    if ( open my $fh, '>', $job->{meta} ) {
        print $fh JSON::PP->new()->encode($meta);
        close $fh;
    }
    else {
        $result->error( 'Cannot record job: [_1].', "$!" );
        return;
    }
    _prune_jobs($home);
    $result->data(
        {
            job_id => $job_id,
            state  => defined $early ? 'done' : 'running',
            %{ $extra_hr // {} },
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_deploy_info - Composer/Node availability, quota, cron and
#   maintenance state for the deploy panel. The page hides each button whose
#   binary is not found.
#-------------------------------------------------------------------------------------------------
sub app_helper_deploy_info {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ( $composer, $composer_err ) = _find_composer();
    my ( $node_bin, $node_source, $node_warn ) = _select_node_for_app($approot);
    my $npm = undef;
    if ( defined $node_bin ) {
        ( my $npmdir = $node_bin ) =~ s{/bin/node$}{/bin/npm};
        if ( -f $npmdir && -x $npmdir ) {
            $npm = $npmdir;
        }
    }
    # Read disable_functions from the selected PHP binary as the user.
    # When the host disables proc_open, Composer cannot run: hide the button
    # and explain instead of failing at runtime with a usage dump.
    my ( $php_bin_info, undef, undef ) = _select_php_for_app( $user, $approot );
    my $proc_disabled = 0;
    if ( defined $php_bin_info ) {
        $proc_disabled = _proc_open_disabled( $php_bin_info, $approot ) ? 1 : 0;
    }
    my %composer_out;
    if ($proc_disabled) {
        %composer_out = (
            found  => 0,
            reason => 'Your host has disabled proc_open in PHP, which Composer needs. Ask your host.',
        );
    }
    else {
        %composer_out = (
            found => defined $composer ? 1 : 0,
            defined $composer ? ( path => $composer ) : (),
            defined $composer ? () : ( reason => $composer_err ),
        );
    }
    my $cron   = _cron_state( $user, $home, $approot );
    my $down   = _maintenance_down($approot) ? 1 : 0;
    my $quota  = _quota_info($user);
    $result->data(
        {
            user => $user, app => $app_param,
            composer => \%composer_out,
            node => {
                found => defined $node_bin ? 1 : 0,
                defined $node_bin ? ( bin => $node_bin, npm => $npm ) : (),
                defined $node_warn ? ( warning => $node_warn ) : (),
            },
            quota       => $quota,
            cron        => $cron,
            maintenance => { down => $down },
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_composer_start / app_helper_npm_start - Detached recipe jobs.
#   app_helper_deploy_status / app_helper_deploy_cancel - Follow them up.
#-------------------------------------------------------------------------------------------------
sub app_helper_composer_start {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($rel) = _app_rel( $home, $approot );
    if ( my $live = _deploy_find_live( $home, $rel ) ) {
        $result->data( { state => 'busy', job_id => $live->{id} } );
        return 1;
    }
    my ( $composer, $cerr ) = _find_composer();
    if ( !defined $composer ) {
        $result->error( 'Cannot run composer: [_1].', $cerr );
        return;
    }
    my ( $php_bin, $php_err, $php_source ) = _select_php_for_app( $user, $approot );
    if ( !defined $php_bin ) {
        $result->error( 'No PHP available: [_1].', $php_err );
        return;
    }
    # Refuse when the host disables proc_open, unless the admin
    # explicitly opted into composer_lift_disable_functions=1 (which runs
    # only this Composer process with an empty disable_functions).
    my $policy = eval { _read_user_policy() };
    my $lift = ( ref $policy eq 'HASH' && ( $policy->{composer_lift_disable_functions} // '' ) eq '1' ) ? 1 : 0;
    if ( !$lift && _proc_open_disabled( $php_bin, $approot ) ) {
        $result->error( 'Cannot run composer: [_1]',
            'Your host has disabled proc_open in PHP, which Composer needs. Ask your host.' );
        return;
    }
    my $recipe = _deploy_recipe_composer( $home, $approot, $php_bin, $composer );
    return _deploy_start_job(
        $result, $user, $home, $rel, $approot, 'composer_install', $recipe,
        { php_bin => $php_bin, php_source => $php_source } );
}

sub app_helper_npm_start {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    # Validate the flag before touching anything else (fail fast on bad input).
    my ($keep_p) = $args->get('keep_node_modules');
    my ( $keep_nm, $bool_err ) = _bool_param( $keep_p, 0 );
    if ( defined $bool_err ) {
        $result->error( 'Invalid keep_node_modules: [_1].', $bool_err );
        return;
    }
    my ($rel) = _app_rel( $home, $approot );
    if ( my $live = _deploy_find_live( $home, $rel ) ) {
        $result->data( { state => 'busy', job_id => $live->{id} } );
        return 1;
    }
    my ( $node_bin, $node_source, $node_warn ) = _select_node_for_app($approot);
    if ( !defined $node_bin ) {
        $result->error( 'Cannot build assets: [_1].', $node_warn // 'no Node.js available' );
        return;
    }
    ( my $npm = $node_bin ) =~ s{/bin/node$}{/bin/npm};
    if ( !-f $npm || !-x $npm ) {
        $result->error( 'Cannot build assets: [_1].', 'npm is missing next to node' );
        return;
    }
    if ( !_package_has_build_script($approot) ) {
        $result->error( 'Cannot build assets: [_1].', 'package.json has no build script' );
        return;
    }
    my $recipe = _deploy_recipe_npm( $home, $approot, $npm, $keep_nm );
    my $quota  = _quota_info($user);
    return _deploy_start_job(
        $result, $user, $home, $rel, $approot, 'npm_build', $recipe,
        {
            node_bin => $node_bin,
            defined $node_warn ? ( node_warning => $node_warn ) : (),
            defined $quota ? ( quota => $quota ) : (),
            keep_node_modules => $keep_nm ? 1 : 0,
            installer => $recipe->{installer},
        } );
}

sub app_helper_deploy_status {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my $job = _job_paths( $home, $job_id );
    if ( !defined $job || !-f $job->{meta} ) {
        $result->error('Unknown job.');
        return;
    }
    my $meta = _read_json_file( $job->{meta} );
    if ( !$meta || ( $meta->{tool} // '' ) ne 'deploy' ) {
        $result->error('Unknown job.');
        return;
    }
    my $final = _read_json_file( $job->{result} );
    if ( $final && ref $final eq 'HASH' && defined $final->{ok} ) {
        if ( $final->{cancelled} ) {
            $result->data( { job_id => $job_id, state => 'cancelled', log => _deploy_log_tail($job) } );
            return 1;
        }
        # Say what happened to node_modules (npm jobs only). kept =
        # user ticked keep, or cleanup failed and it is still on disk.
        my $nm;
        if ( ( $meta->{recipe} // '' ) eq 'npm_build' ) {
            if ( $meta->{keep_node_modules} ) {
                $nm = 'kept';
            }
            elsif ( ( $final->{cleanup} // '' ) eq 'removed' ) {
                $nm = 'removed-cleanup';
            }
            elsif ( $final->{ok}
                && grep { ( $_->{name} // '' ) eq 'remove node_modules' && ( $_->{exit} // -1 ) == 0 }
                @{ $final->{steps} // [] } )
            {
                $nm = 'removed';
            }
            else {
                $nm = 'kept';
            }
        }
        # LVE-killed npm/composer steps report plain words, never a raw
        # exit code. The log tail stays for detail; the hint is the summary.
        my $log_tail = _deploy_log_tail($job);
        my $hint;
        if ( !$final->{ok} ) {
            $hint = _deploy_lve_hint( $final, $log_tail );
        }
        _activity_log_job_done( $home, 'app_helper', $job_id, undef,
            ( $meta->{recipe} // 'deploy' ) . ' done' );
        $result->data(
            {
                job_id => $job_id, state => $final->{ok} ? 'done' : 'failed',
                result => $final, log => $log_tail,
                defined $nm ? ( node_modules => $nm ) : (),
                defined $hint ? ( resource_hint => $hint ) : (),
            }
        );
        return 1;
    }
    if ( -f $job->{cancelled} ) {
        $result->data( { job_id => $job_id, state => 'cancelled', log => _deploy_log_tail($job) } );
        return 1;
    }
    my $pid = $meta->{pid};
    if ( $pid && kill( 0, $pid ) && _proc_owner_ok( $pid, $> ) && _proc_is_recipe_worker($pid) ) {
        my $progress = _read_json_file( $job->{progress} ) // {};
        $result->data(
            {
                job_id => $job_id, state => 'running',
                progress => $progress, log => _deploy_log_tail($job),
            }
        );
        return 1;
    }
    $result->data(
        {
            job_id => $job_id, state => 'failed',
            error => 'The worker is gone without a result.',
            log => _deploy_log_tail($job),
            ( ( $meta->{recipe} // '' ) eq 'npm_build' ) ? ( node_modules => 'kept' ) : (),
        }
    );
    return 1;
}

sub app_helper_deploy_cancel {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($job_id) = $args->get('job_id');
    my $job = _job_paths( $home, $job_id );
    if ( !defined $job || !-f $job->{meta} ) {
        $result->error('Unknown job.');
        return;
    }
    my $meta = _read_json_file( $job->{meta} );
    if ( !$meta || ( $meta->{tool} // '' ) ne 'deploy' || !$meta->{pid} ) {
        $result->error('Unknown job.');
        return;
    }
    my $pid = $meta->{pid};
    if ( !kill( 0, $pid ) || !_proc_owner_ok( $pid, $uid ) || !_proc_is_recipe_worker($pid) ) {
        $result->data( { job_id => $job_id, cancelled => 0, reason => 'not running (already finished)' } );
        return 1;
    }
    # Signal the WORKER first: its SIGTERM handler kills the current step's
    # group the same way timeouts do, writes {cancelled:true} and exits.
    # Only if it survives 10 s do we killpg the worker group as a fallback.
    kill( 'TERM', $pid );
    my $waited = 0;
    while ( $waited < $DEPLOY_CANCEL_GRACE ) {
        last unless kill( 0, $pid );
        usleep(100000);
        $waited += 0.1;
    }
    if ( kill( 0, $pid ) ) {
        if ( _proc_owner_ok( $pid, $uid ) && _proc_is_recipe_worker($pid) ) {
            kill( 'KILL', -$pid );
            for ( 1 .. 50 ) {
                last unless kill( 0, $pid );
                usleep(100000);
            }
        }
    }
    if ( kill( 0, $pid ) ) {
        $result->data( { job_id => $job_id, cancelled => 0, reason => 'still running; try again' } );
        return 1;
    }
    if ( open my $fh, '>', $job->{cancelled} ) {
        print $fh time(), "\n";
        close $fh;
        chmod 0600, $job->{cancelled};
    }
    _activity_log( $home, 'app_helper', 'cancel job',
        { job_id => $job_id, recipe => $meta->{recipe} // '' }, undef );
    $result->data( { job_id => $job_id, cancelled => 1 } );
    return 1;
}

sub _app_rel {
    my ( $home, $approot ) = @_;
    # Home-relative app path (approot is always under home by construction).
    if ( $approot eq $home ) {
        return '';
    }
    if ( index( $approot, "$home/" ) == 0 ) {
        return substr( $approot, length("$home/") );
    }
    return $approot;
}

sub _package_has_build_script {
    my ($approot) = @_;
    my $file = "$approot/package.json";
    my @st = lstat $file;
    if ( !@st || -l _ || !-f _ || $st[7] > 262144 ) {
        return 0;
    }
    if ( open my $fh, '<', $file ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' && ref $data->{scripts} eq 'HASH' ) {
            return defined $data->{scripts}{build} && !ref $data->{scripts}{build} ? 1 : 0;
        }
    }
    return 0;
}

sub _artisan_fixed {
    my ( $user, $home, $approot, $cmd_ar, $timeout ) = @_;
    # Quick fixed-argv artisan runs (down/up/queue/key/config): PHP
    # selection, vendor check, spawn, friendly errors, LVE hint. $cmd_ar
    # holds the artisan-side argv WITHOUT php (fixed by the caller).
    # Returns a result hash (never dies on spawn trouble).
    my ( $php_bin, $php_err, $php_source ) = _select_php_for_app( $user, $approot );
    if ( !defined $php_bin ) {
        return { ok => 0, error => "No PHP available: $php_err" };
    }
    if ( !-f "$approot/vendor/autoload.php" ) {
        return {
            ok => 0, friendly => 'no_vendor',
            detail => 'vendor/ is missing. Run composer install for this app first.',
            php_bin => $php_bin, php_source => $php_source,
        };
    }
    my $res = _spawn_sync(
        [ $php_bin, "$approot/artisan", @{$cmd_ar} ], $approot,
        { PATH => '/usr/local/bin:/usr/bin:/bin', HOME => $home, LANG => 'C.UTF-8' },
        defined $timeout ? $timeout : 120, $ARTISAN_OUTPUT_CAP,
    );
    my $failed = $res->{timed_out} || $res->{exit} != 0;
    my %out = (
        ok => $failed ? 0 : 1, php_bin => $php_bin, php_source => $php_source,
        output => $res->{output}, exit => $res->{exit} + 0,
        truncated => $res->{truncated} ? 1 : 0,
        timed_out => $res->{timed_out} ? 1 : 0,
        resource_hint => _lve_hint($res),
    );
    if ( $res->{error} ) {
        $out{detail} = 'Could not start the command.';
        return \%out;
    }
    if ($failed) {
        $out{friendly} = _friendly_artisan_error( $approot, 0, $res );
    }
    return \%out;
}

sub _maintenance_down {
    my ($approot) = @_;
    # Laravel's maintenance flag (both historical and current filenames).
    return ( -f "$approot/storage/framework/maintenance.php" || -f "$approot/storage/framework/down" ) ? 1 : 0;
}

sub _random_hex_secret {
    # 32 hex characters from /dev/urandom, generated server-side.
    if ( open my $fh, '<', '/dev/urandom' ) {
        my $bytes = '';
        my $n = read( $fh, $bytes, 16 );
        close $fh;
        if ( defined $n && $n == 16 ) {
            return unpack( 'H*', $bytes );
        }
    }
    return undef;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_maintenance {app, action} - Down (secret bypass URL) / Up.
#-------------------------------------------------------------------------------------------------
sub app_helper_maintenance {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($action) = $args->get('action');
    if ( !defined $action || ( $action ne 'down' && $action ne 'up' ) ) {
        $result->error( 'Invalid action: [_1].', 'must be down or up' );
        return;
    }
    if ( $action eq 'up' ) {
        my $run = _artisan_fixed( $user, $home, $approot, ['up'] );
        if ( $run->{error} ) {
            $result->error( 'Maintenance change failed: [_1].', $run->{error} );
            return;
        }
        _activity_log( $home, 'app_helper', 'maintenance up',
            { app => $app_param }, undef );
        $result->data( { user => $user, app => $app_param, action => 'up', %{$run} } );
        return 1;
    }
    my $secret = _random_hex_secret();
    if ( !defined $secret || $secret !~ /^[0-9a-f]{32}$/ ) {
        $result->error('Could not generate a secret; try again.');
        return;
    }
    my $run = _artisan_fixed( $user, $home, $approot, [ 'down', "--secret=$secret" ] );
    if ( $run->{error} || !$run->{ok} ) {
        $result->error( 'Maintenance change failed: [_1].', $run->{error} // $run->{detail} // 'artisan down failed' );
        return;
    }
    my @mapped = _mapped_domains( $user, $approot );
    my $domain = @mapped ? $mapped[0]{domain} : undef;
    _activity_log( $home, 'app_helper', 'maintenance down',
        { app => $app_param }, undef );
    $result->data(
        {
            user => $user, app => $app_param, action => 'down', %{$run},
            secret => $secret,
            defined $domain ? ( bypass_url => "https://$domain/$secret" ) : (),
        }
    );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_logs / app_helper_log_view / app_helper_log_clear - storage logs.
#-------------------------------------------------------------------------------------------------
sub _logs_dir {
    my ($approot) = @_;
    return "$approot/storage/logs";
}

sub _valid_log_name {
    my ($name) = @_;
    return ( defined $name && $name =~ /^[A-Za-z0-9._-]+\.log$/ ) ? 1 : 0;
}

sub _list_logs {
    my ($approot) = @_;
    my $dir = _logs_dir($approot);
    my $dh;
    if ( !opendir( $dh, $dir ) ) {
        return [];
    }
    my @files = grep { -f "$dir/$_" } readdir $dh;
    closedir $dh;
    my @out;
    for my $f ( sort @files ) {
        next unless _valid_log_name($f);
        my @st = lstat "$dir/$f";
        next unless @st && !-l _ && -f _;
        my $size = $st[7];
        my $state = 'ok';
        if ( $size > 200 * 1024 * 1024 ) {
            $state = 'critical';
        }
        elsif ( $size > 50 * 1024 * 1024 ) {
            $state = 'warning';
        }
        push @out, { name => $f, size => $size + 0, state => $state, mtime => $st[9] + 0 };
    }
    @out = sort { $b->{mtime} <=> $a->{mtime} } @out;
    return \@out;
}

sub _open_log_nofollow {
    my ( $approot, $name, $mode ) = @_;
    # Returns an open fd or (undef, reason): lstat first, then O_NOFOLLOW,
    # then fstat must be a regular file. Symlinks are always refused.
    if ( !_valid_log_name($name) ) {
        return ( undef, 'unknown log file' );
    }
    my $path = _logs_dir($approot) . "/$name";
    my @st = lstat $path;
    if ( !@st ) {
        return ( undef, 'unknown log file' );
    }
    if ( -l _ ) {
        return ( undef, 'refusing symlink' );
    }
    require Fcntl;
    my $flags = $mode eq 'read' ? Fcntl::O_RDONLY() : Fcntl::O_WRONLY();
    $flags |= Fcntl::O_NOFOLLOW();
    my $fh;
    if ( !sysopen( $fh, $path, $flags ) ) {
        return ( undef, "cannot open log: $!" );
    }
    my @fst = stat $fh;
    if ( !@fst || !-f _ ) {
        close $fh;
        return ( undef, 'not a regular file' );
    }
    return ( $fh, undef );
}

sub app_helper_logs {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my $logs = _list_logs($approot);
    my $advice = _log_rotation_advice($approot);
    $result->data( { user => $user, app => $app_param, logs => $logs, advice => $advice } );
    return 1;
}

sub _log_rotation_advice {
    my ($approot) = @_;
    # Copy-ready snippet when daily rotation is not configured. The .env
    # values themselves are never returned — only whether the keys exist.
    my $env = _read_dotenv_pairs("$approot/.env");
    if ( !defined $env ) {
        return undef;
    }
    my %has = map { $_ => 1 } keys %{$env};
    if ( !$has{LOG_STACK} && !( $has{LOG_CHANNEL} && $env->{LOG_CHANNEL} ne 'single' ) ) {
        return 'Consider LOG_STACK=daily with LOG_DAILY_DAYS=14 in .env so logs rotate instead of growing.';
    }
    return undef;
}

sub app_helper_log_view {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($name) = $args->get('name');
    my ( $fh, $err ) = _open_log_nofollow( $approot, $name, 'read' );
    if ( !defined $fh ) {
        $result->error( 'Cannot view log: [_1].', $err );
        return;
    }
    # Tail by seeking from the end: never read a huge file whole. At most
    # LOG_VIEW_BYTES, then the last LOG_VIEW_LINES lines.
    my $size = ( stat($fh) )[7] // 0;
    if ( $size > $LOG_VIEW_BYTES ) {
        seek( $fh, $size - $LOG_VIEW_BYTES, 0 );
        <$fh>;
    }
    local $/;
    my $chunk = <$fh>;
    close $fh;
    $chunk = '' unless defined $chunk;
    my @lines = split /\n/, $chunk, -1;
    if ( @lines && $lines[-1] eq '' ) {
        pop @lines;
    }
    if ( @lines > $LOG_VIEW_LINES ) {
        @lines = @lines[ $#lines - $LOG_VIEW_LINES + 1 .. $#lines ];
    }
    $result->data(
        { user => $user, app => $app_param, name => $name, size => $size + 0, tail => _strip_ansi( join( "\n", @lines ) ) } );
    return 1;
}

sub app_helper_log_clear {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($name) = $args->get('name');
    my ( $fh, $err ) = _open_log_nofollow( $approot, $name, 'write' );
    if ( !defined $fh ) {
        $result->error( 'Cannot clear log: [_1].', $err );
        return;
    }
    # Truncate on the opened fd (no unlink/recreate races). No undo.
    if ( !truncate( $fh, 0 ) ) {
        close $fh;
        $result->error( 'Cannot clear log: [_1].', "$!" );
        return;
    }
    close $fh;
    _activity_log( $home, 'app_helper', 'clear log',
        { app => $app_param, name => $name }, undef );
    $result->data( { user => $user, app => $app_param, name => $name, cleared => 1 } );
    return 1;
}

# ---------------------------------------------------------------------------
# Scheduler cron through the user's own crontab (there is no UAPI Cron
# module on 11.138 — only API 2 has one). The UAPI module already runs as
# the user, so it reads with `crontab -l` and writes with `crontab -`
# (argv lists, no shell; stdin/stdout/stderr are files and pipes, never a
# shell string). Lines we add are preceded by a marker comment holding the
# sha1 of the absolute app path; detection and removal only ever touch our
# marker plus the following line, and only when that line still contains
# `artisan schedule:run` and the app path. Everything else — MAILTO,
# comments, other lines, the trailing newline — is preserved byte-for-byte.
# ---------------------------------------------------------------------------

sub _crontab_bin {
    return defined $TEST_CRONTAB ? $TEST_CRONTAB : 'crontab';
}

sub _crontab_run {
    my ( $args_ar, $input ) = @_;
    # Run crontab with argv (no shell). $input (undef = none) travels to the
    # child's stdin through a PIPE (never a shell string, never a temp
    # file); stdout through a pipe, stderr to a temp file. Content is capped
    # at 64 KB by callers, well within pipe capacity, and crontab's own
    # output is tiny, so neither side can block forever. Returns
    # (stdout, stderr, exit); exit is undef when the spawn itself failed.
    require File::Temp;
    my $bin = _crontab_bin();
    my ( $out_rd, $out_wr );
    if ( !pipe( $out_rd, $out_wr ) ) {
        return ( undef, "cannot create pipe: $!", undef );
    }
    my ( $in_rd, $in_wr );
    if ( defined $input ) {
        if ( !pipe( $in_rd, $in_wr ) ) {
            close $out_rd;
            close $out_wr;
            return ( undef, "cannot create pipe: $!", undef );
        }
    }
    my $errtmp = File::Temp->new( UNLINK => 1 );
    my $errfile = "$errtmp";
    close $errtmp;
    my $kid = fork();
    if ( !defined $kid ) {
        close $out_rd;
        close $out_wr;
        close $in_rd if defined $input;
        close $in_wr if defined $input;
        return ( undef, "cannot fork: $!", undef );
    }
    if ( $kid == 0 ) {
        close $out_rd;
        if ( defined $input ) {
            close $in_wr;
            open STDIN, '<&', $in_rd or POSIX::_exit(127);
        }
        else {
            open STDIN, '<', '/dev/null' or POSIX::_exit(127);
        }
        open STDOUT, '>&', $out_wr or POSIX::_exit(127);
        open STDERR, '>', $errfile or POSIX::_exit(127);
        close $out_wr;
        close $in_rd if defined $input;
        exec { $bin } ( $bin, @{$args_ar} ) or POSIX::_exit(127);
    }
    close $out_wr;
    if ( defined $input ) {
        close $in_rd;
        my $off = 0;
        while ( $off < length($input) ) {
            my $n = syswrite( $in_wr, $input, length($input) - $off, $off );
            if ( !defined $n ) {
                last;
            }
            $off += $n;
        }
        close $in_wr;
    }
    local $/;
    my $out = <$out_rd>;
    close $out_rd;
    waitpid( $kid, 0 );
    my $exit = $? >> 8;
    my $err = '';
    if ( open my $efh, '<', $errfile ) {
        local $/;
        $err = <$efh> // '';
        close $efh;
    }
    return ( $out // '', $err, $exit );
}

sub _cron_marker_for {
    my ($approot) = @_;
    require Digest::SHA;
    return '# usertools:schedule ' . Digest::SHA::sha1_hex($approot);
}

sub _cron_read {
    # Returns (content, undef), ('' for no crontab), or (undef, reason).
    # Only stdout is read: CloudLinux's crontab wrapper prints
    # "Backup of <user>'s previous crontab saved to ..." on stderr, which
    # is ignored here (a banner on stderr never breaks the read).
    my ( $out, $err, $exit ) = _crontab_run( ['-l'], undef );
    if ( !defined $exit ) {
        return ( undef, $out // 'cannot run crontab' );
    }
    if ( $exit == 0 ) {
        return ( $out, undef );
    }
    if ( $err =~ /no crontab/i ) {
        return ( '', undef );
    }
    return ( undef, 'cannot read crontab' );
}

sub _cron_write {
    my ($content) = @_;
    # Feeds the whole new crontab via `crontab -`. Returns undef on success,
    # else a reason. Callers check the 64 KB cap first. Every line written
    # back must be a comment, blank, an environment assignment or a cron
    # entry — garbage on stdout is refused, never written.
    if ( !_cron_content_valid($content) ) {
        return 'refusing to write unrecognized crontab content';
    }
    my ( $out, $err, $exit ) = _crontab_run( ['-'], $content );
    if ( !defined $exit || $exit != 0 ) {
        return 'cannot write crontab';
    }
    return undef;
}

sub _cron_stripped {
    my ($line) = @_;
    ( my $s = $line ) =~ s/\r?\n$//;
    return $s;
}

sub _cron_is_blank {
    my ($line) = @_;
    return _cron_stripped($line) =~ /^\s*$/ ? 1 : 0;
}

sub _cron_is_env {
    my ($line) = @_;
    return _cron_stripped($line) =~ /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/ ? 1 : 0;
}

sub _cron_is_comment {
    my ($line) = @_;
    return _cron_stripped($line) =~ /^\s*#/ ? 1 : 0;
}

sub _cron_is_cron_entry {
    my ($line) = @_;
    my $s = _cron_stripped($line);
    return 1 if $s =~ /^\s*\@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)\s+\S/;
    return 1
      if $s =~ /^\s*[\*\d,\/\-]+\s+[\*\d,\/\-]+\s+[\*\d,\/\-]+\s+[\*\d,\/\-]+\s+[\*\d,\/\-]+\s+\S/;
    return 0;
}

sub _cron_content_valid {
    # Every line must be a comment, blank, env assignment or cron entry.
    my ($content) = @_;
    return 1 unless defined $content && $content ne '';
    for my $line ( split /(?<=\n)/, $content ) {
        next if _cron_is_blank($line);
        next if _cron_is_comment($line);
        next if _cron_is_env($line);
        next if _cron_is_cron_entry($line);
        return 0;
    }
    return 1;
}

sub _cron_split_lines {
    my ($content) = @_;
    return [ split /(?<=\n)/, $content ];
}

sub _cron_find_marker {
    my ( $lines_ar, $marker ) = @_;
    for my $i ( 0 .. $#{$lines_ar} ) {
        ( my $l = $lines_ar->[$i] ) =~ s/\r?\n$//;
        if ( $l eq $marker ) {
            return $i;
        }
    }
    return undef;
}

sub _cron_next_matches {
    my ( $lines_ar, $idx, $approot ) = @_;
    my $next = $lines_ar->[ $idx + 1 ];
    return 0 unless defined $next;
    ( my $s = $next ) =~ s/\r?\n$//;
    return ( $s =~ /artisan schedule:run/ && index( $s, $approot ) >= 0 ) ? 1 : 0;
}

sub _cron_find_command {
    # CloudLinux's crontab wrapper rewrites the crontab and inserts
    # SHELL="..." (and other NAME=value environment lines) between our
    # marker and our command line. After the marker, skip blank and
    # NAME=value lines; the first command line must still contain
    # `artisan schedule:run` and the app path. Returns the command index
    # or undef when the block was edited by hand.
    my ( $lines_ar, $idx, $approot ) = @_;
    my $j = $idx + 1;
    while ( $j <= $#{$lines_ar} ) {
        if ( _cron_is_blank( $lines_ar->[$j] ) || _cron_is_env( $lines_ar->[$j] ) ) {
            $j++;
            next;
        }
        last;
    }
    return undef if $j > $#{$lines_ar};
    ( my $s = $lines_ar->[$j] ) =~ s/\r?\n$//;
    return ( $s =~ /artisan schedule:run/ && index( $s, $approot ) >= 0 ) ? $j : undef;
}

sub _cron_journal_file {
    my ($home) = @_;
    return "$home/.cpanel/usertools/cron.json";
}

sub _read_cron_journal {
    my ($home) = @_;
    if ( open my $fh, '<', _cron_journal_file($home) ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' && ref $data->{lines} eq 'HASH' ) {
            return $data->{lines};
        }
    }
    return {};
}

sub _write_cron_journal {
    my ( $home, $lines_hr ) = @_;
    my $dir = "$home/.cpanel/usertools";
    eval { make_path( $dir, { mode => 0700 } ) };
    return 0 if $@;
    my $file = _cron_journal_file($home);
    my $tmp  = "$file.tmp.$$";
    my $fh;
    if ( !open $fh, '>', $tmp ) {
        return 0;
    }
    print $fh JSON::PP->new()->canonical(1)->encode( { lines => $lines_hr } );
    close $fh;
    chmod 0600, $tmp;
    return rename( $tmp, $file ) ? 1 : 0;
}

sub _cron_state {
    my ( $user, $home, $approot ) = @_;
    my ( $content, $err ) = _cron_read();
    if ( !defined $content ) {
        return { available => 0, present => 0 };
    }
    my $marker = _cron_marker_for($approot);
    my $lines  = _cron_split_lines($content);
    my $idx    = _cron_find_marker( $lines, $marker );
    if ( defined $idx && defined _cron_find_command( $lines, $idx, $approot ) ) {
        return { available => 1, present => 1 };
    }
    return { available => 1, present => 0 };
}

sub _cron_command_for {
    my ( $approot, $php_bin ) = @_;
    # Built server-side, fixed shape. The app path obeys the same
    # [A-Za-z0-9/_.-] rule as the <If> path; the PHP path is allowlisted.
    if ( $approot !~ m{^[A-Za-z0-9/_.-]+$} ) {
        return ( undef, 'unsafe app path for the scheduler' );
    }
    if ( !_php_bin_allowed($php_bin) ) {
        return ( undef, 'unsafe PHP path for the scheduler' );
    }
    ( my $app_q = $approot ) =~ s/'/'\\''/g;
    ( my $php_q = $php_bin ) =~ s/'/'\\''/g;
    return ( "* * * * * cd '$app_q' && '$php_q' artisan schedule:run >> /dev/null 2>&1", undef );
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_cron_status / app_helper_cron_add / app_helper_cron_remove
#-------------------------------------------------------------------------------------------------
sub app_helper_cron_status {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my $state = _cron_state( $user, $home, $approot );
    $result->data( { user => $user, app => $app_param, %{$state} } );
    return 1;
}

sub app_helper_cron_add {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($rel) = _app_rel( $home, $approot );
    my ( $content, $rerr ) = _cron_read();
    if ( !defined $content ) {
        $result->error( 'Cannot read scheduler: [_1].', $rerr );
        return;
    }
    if ( length($content) > 65536 ) {
        $result->error( 'Cannot change scheduler: [_1].', 'crontab is too large' );
        return;
    }
    my ( $php_bin, $php_err, $php_source ) = _select_php_for_app( $user, $approot );
    if ( !defined $php_bin ) {
        $result->error( 'No PHP available: [_1].', $php_err );
        return;
    }
    my ( $command, $cerr ) = _cron_command_for( $approot, $php_bin );
    if ( !defined $command ) {
        $result->error( 'Invalid scheduler line: [_1].', $cerr );
        return;
    }
    my $marker = _cron_marker_for($approot);
    my $lines  = _cron_split_lines($content);
    my $idx    = _cron_find_marker( $lines, $marker );
    if ( defined $idx ) {
        my $cmd_idx = _cron_find_command( $lines, $idx, $approot );
        if ( !defined $cmd_idx ) {
            $result->error( 'Cannot change scheduler: [_1].',
                'the scheduler block was edited by hand; remove those lines first' );
            return;
        }
        ( my $have = $lines->[$cmd_idx] ) =~ s/\r?\n$//;
        my $journal = _read_cron_journal($home);
        $journal->{$rel} = { marker => $marker, command => $command, added => time() };
        _write_cron_journal( $home, $journal );
        if ( $have eq $command ) {
            $result->data( { user => $user, app => $app_param, present => 1, added => 0, command => $command } );
            return 1;
        }
        my $ending = ( $lines->[$cmd_idx] =~ /(\r?\n)$/ ) ? $1 : "\n";
        $lines->[$cmd_idx] = $command . $ending;
        my $werr = _cron_write( join( '', @{$lines} ) );
        if ( defined $werr ) {
            $result->error( 'Cannot change scheduler: [_1].', $werr );
            return;
        }
        $result->data(
            { user => $user, app => $app_param, present => 1, added => 1, updated => 1, command => $command } );
        return 1;
    }
    my $new = $content;
    if ( $new ne '' && $new !~ /\n$/ ) {
        $new .= "\n";
    }
    $new .= "$marker\n$command\n";
    my $werr = _cron_write($new);
    if ( defined $werr ) {
        $result->error( 'Cannot change scheduler: [_1].', $werr );
        return;
    }
    my $journal = _read_cron_journal($home);
    $journal->{$rel} = { marker => $marker, command => $command, added => time() };
    _write_cron_journal( $home, $journal );
    _activity_log( $home, 'app_helper', 'scheduler add',
        { app => $app_param },
        { fn => 'app_helper_cron_remove', args => { app => $app_param } } );
    $result->data( { user => $user, app => $app_param, present => 1, added => 1, command => $command } );
    return 1;
}

sub app_helper_cron_remove {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($rel) = _app_rel( $home, $approot );
    my $journal = _read_cron_journal($home);
    my $rec     = $journal->{$rel};
    if ( !defined $rec ) {
        $result->error('Nothing to remove: this tool added no scheduler line for this app.');
        return;
    }
    # Removal touches ONLY our marker plus the command line, and only when
    # that line still contains `artisan schedule:run` and the app path. A
    # hand-edited block is left alone. CloudLinux's wrapper may insert
    # SHELL="..." (or other NAME=value lines) between the two: those
    # environment lines are kept, not removed.
    my ( $content, $rerr ) = _cron_read();
    if ( !defined $content ) {
        $result->error( 'Cannot read scheduler: [_1].', $rerr );
        return;
    }
    if ( length($content) > 65536 ) {
        $result->error( 'Cannot change scheduler: [_1].', 'crontab is too large' );
        return;
    }
    my $marker = ( ref $rec eq 'HASH' && defined $rec->{marker} ) ? $rec->{marker} : _cron_marker_for($approot);
    my $lines  = _cron_split_lines($content);
    my $idx    = _cron_find_marker( $lines, $marker );
    my $cmd_idx = defined $idx ? _cron_find_command( $lines, $idx, $approot ) : undef;
    if ( !defined $idx || !defined $cmd_idx ) {
        $result->error('The recorded scheduler line is gone or unrecognized; ask your host.');
        return;
    }
    # Remove the command first (higher index), then the marker, so any
    # environment lines the wrapper added in between are kept.
    splice( @{$lines}, $cmd_idx, 1 );
    splice( @{$lines}, $idx, 1 );
    my $werr = _cron_write( join( '', @{$lines} ) );
    if ( defined $werr ) {
        $result->error( 'Cannot change scheduler: [_1].', $werr );
        return;
    }
    delete $journal->{$rel};
    _write_cron_journal( $home, $journal );
    _activity_log( $home, 'app_helper', 'scheduler remove',
        { app => $app_param },
        { fn => 'app_helper_cron_add', args => { app => $app_param } } );
    $result->data( { user => $user, app => $app_param, present => 0, removed => 1 } );
    return 1;
}

# ---------------------------------------------------------------------------
# Strict .env parsing: recognise KEY=value, KEY="value", KEY='value' and
# export KEY=...; preserve comments, blank lines, order, endings and quote
# style. Values of other keys are NEVER returned — only flags about them.
# ---------------------------------------------------------------------------

sub _parse_dotenv_lines {
    my ($content) = @_;
    # Returns an array of line records {ending, type, key?, value?, quote?,
    # export?, raw}. type is blank/comment/kv/raw.
    my @lines = split /(?<=\n)/, $content;
    my @out;
    for my $line (@lines) {
        my $ending = '';
        if ( $line =~ s/(\r?\n)$// ) {
            $ending = $1;
        }
        my %rec = ( ending => $ending, raw => $line );
        if ( $line =~ /^\s*$/ ) {
            $rec{type} = 'blank';
        }
        elsif ( $line =~ /^\s*#/ ) {
            $rec{type} = 'comment';
        }
        elsif ( $line =~ /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/s ) {
            my ( $key, $rest ) = ( $1, $2 );
            my $export = $line =~ /^\s*export\s+/ ? 1 : 0;
            my ( $value, $quote ) = ( '', '' );
            if ( $rest =~ /^\s*"(.*)$/s ) {
                my $inner = $1;
                if ( $inner =~ /^(.*?)((?<!\\)")\s*$/s ) {
                    $inner = $1;
                    $quote = '"';
                }
                else {
                    $quote = '"';
                }
                $value = $inner;
            }
            elsif ( $rest =~ /^\s*'(.*)$/s ) {
                my $inner = $1;
                if ( $inner =~ /^(.*?)'\s*$/s ) {
                    $inner = $1;
                    $quote = "'";
                }
                else {
                    $quote = "'";
                }
                $value = $inner;
            }
            else {
                ( my $bare = $rest ) =~ s/\s+$//;
                $value = $bare;
                $quote = '';
            }
            %rec = ( %rec, type => 'kv', key => $key, value => $value, quote => $quote, export => $export );
        }
        else {
            $rec{type} = 'raw';
        }
        push @out, \%rec;
    }
    return \@out;
}

sub _read_dotenv_pairs {
    my ($path) = @_;
    # Tolerant KEY=>value map for readiness/advice (values stay server-side;
    # callers must only return flags). Undef when unreadable.
    my @st = lstat $path;
    if ( !@st || -l _ || !-f _ ) {
        return undef;
    }
    if ( open my $fh, '<', $path ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        if ( defined $raw ) {
            my %pairs;
            for my $rec ( @{ _parse_dotenv_lines($raw) } ) {
                if ( $rec->{type} eq 'kv' ) {
                    $pairs{ $rec->{key} } = $rec->{value};
                }
            }
            return \%pairs;
        }
    }
    return undef;
}

sub _read_dotenv_file {
    my ( $home, $uid, $approot ) = @_;
    # Guarded read for writes: refuses symlinks, non-owned files and files
    # over 64 KB. Returns (content, undef) or (undef, reason).
    my $path = "$approot/.env";
    my @st = lstat $path;
    if ( !@st ) {
        return ( undef, 'no .env file in this app' );
    }
    if ( -l _ ) {
        return ( undef, '.env is a symlink; refusing' );
    }
    if ( !-f _ ) {
        return ( undef, 'no .env file in this app' );
    }
    if ( $st[4] != $uid ) {
        return ( undef, '.env is not owned by you; ask your host' );
    }
    if ( $st[7] > $DOTENV_MAX_BYTES ) {
        return ( undef, '.env is too large to edit safely' );
    }
    if ( open my $fh, '<', $path ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        if ( defined $raw ) {
            return ( $raw, undef );
        }
    }
    return ( undef, 'cannot read .env' );
}

sub _dotenv_set_keys {
    my ( $lines_ar, $wanted_hr ) = @_;
    # Returns the new content with ONLY the wanted keys changed (or appended
    # when missing), preserving everything else byte-for-byte.
    my %done;
    my @out;
    for my $rec ( @{$lines_ar} ) {
        if ( $rec->{type} eq 'kv' && exists $wanted_hr->{ $rec->{key} } && !$done{ $rec->{key} } ) {
            $done{ $rec->{key} } = 1;
            my $newval = $wanted_hr->{ $rec->{key} };
            my $val = $rec->{quote} eq '"' ? qq{"$newval"} : $rec->{quote} eq "'" ? qq{'$newval'} : $newval;
            my $line = ( $rec->{export} ? 'export ' : '' ) . "$rec->{key}=$val";
            push @out, $line . $rec->{ending};
        }
        else {
            push @out, $rec->{raw} . $rec->{ending};
        }
    }
    for my $k ( sort keys %{$wanted_hr} ) {
        if ( !$done{$k} ) {
            push @out, "$k=$wanted_hr->{$k}\n";
        }
    }
    return join( '', @out );
}

sub _env_orig_journal_file {
    my ($home) = @_;
    return "$home/.cpanel/usertools/env.json";
}

sub _read_env_orig_journal {
    my ($home) = @_;
    if ( open my $fh, '<', _env_orig_journal_file($home) ) {
        local $/;
        my $raw = <$fh>;
        close $fh;
        my $data = eval { JSON::PP->new()->decode( $raw // '' ) };
        if ( !$@ && ref $data eq 'HASH' && ref $data->{files} eq 'HASH' ) {
            return $data->{files};
        }
    }
    return {};
}

sub _write_env_orig_journal {
    my ( $home, $files_hr ) = @_;
    my $dir = "$home/.cpanel/usertools";
    eval { make_path( $dir, { mode => 0700 } ) };
    return 0 if $@;
    my $file = _env_orig_journal_file($home);
    my $tmp  = "$file.tmp.$$";
    my $fh;
    if ( !open $fh, '>', $tmp ) {
        return 0;
    }
    print $fh JSON::PP->new()->canonical(1)->encode( { files => $files_hr } );
    close $fh;
    chmod 0600, $tmp;
    return rename( $tmp, $file ) ? 1 : 0;
}

sub _env_backup {
    my ($path) = @_;
    # Rolling backup for .env: <file>.usertools-bak-<ts>, 0600, last 3.
    my $base = "$path.usertools-bak-" . time();
    my $bak  = $base;
    my $n    = 0;
    while ( -e $bak ) {
        $n++;
        $bak = "$base-$n";
    }
    my $content = eval { _read_text_file($path) };
    if ( $@ || !defined $content ) {
        return undef;
    }
    if ( !_write_text_file( $bak, $content, 0600 ) ) {
        return undef;
    }
    my @all = sort glob "$path.usertools-bak-*";
    while ( @all > 3 ) {
        my $old = shift @all;
        unlink $old;
    }
    return $bak;
}

sub _readiness_flags {
    my ( $user, $home, $uid, $approot ) = @_;
    # Production readiness, read-only. Returns booleans/enums/counts only —
    # never secret values.
    my $pairs = _read_dotenv_pairs("$approot/.env");
    my %env = ref $pairs eq 'HASH' ? %{$pairs} : ();
    my $debug = ( $env{APP_DEBUG} // '' ) =~ /^(true|1)$/i ? 1 : 0;
    my $prod  = ( $env{APP_ENV} // '' ) eq 'production' ? 1 : 0;
    my $key_empty = !( defined $env{APP_KEY} && $env{APP_KEY} ne '' );
    my @mapped = _mapped_domains( $user, $approot );
    my $storage_link = -e "$approot/public/storage" ? 1 : 0;
    my $big_log_mb = 0;
    for my $log ( @{ _list_logs($approot) } ) {
        my $mb = int( $log->{size} / ( 1024 * 1024 ) );
        if ( $mb > $big_log_mb ) {
            $big_log_mb = $mb;
        }
    }
    my $probe   = _env_probe_app( $user, $approot );
    my $checked = ref $probe->{checked} eq 'ARRAY' ? $probe->{checked} : [];
    my $crit = scalar grep { $_->{verdict} eq 'critical' } @{$checked};
    my $config_cache = 'missing';
    if ( -f "$approot/bootstrap/cache/config.php" ) {
        $config_cache = 'fresh';
        my @est = lstat "$approot/.env";
        my @cst = lstat "$approot/bootstrap/cache/config.php";
        if ( @est && @cst && $est[9] > $cst[9] ) {
            $config_cache = 'stale';
        }
    }
    return {
        live         => @mapped ? 1 : 0,
        mapped       => scalar @mapped,
        debug_true   => $debug,
        env_production => $prod,
        key_empty    => $key_empty ? 1 : 0,
        storage_link => $storage_link,
        big_log_mb   => $big_log_mb + 0,
        env_exposed  => $crit ? 1 : 0,
        config_cache => $config_cache,
        proc_open_disabled => _proc_open_disabled_for_app( $user, $approot ),
        missing_extensions => _missing_extensions_for_app( $user, $approot ),
    };
}

sub _proc_open_disabled_for_app {
    # 1 when the selected PHP disables proc_open, else 0. Undef-safe:
    # unknown PHP or unreadable ini reads as 0 (not disabled).
    my ( $user, $approot ) = @_;
    my ( $php_bin, undef, undef ) = _select_php_for_app( $user, $approot );
    return 0 unless defined $php_bin;
    return _proc_open_disabled( $php_bin, $approot ) ? 1 : 0;
}

sub _missing_extensions_for_app {
    # Sorted short names the app needs (ext-* requirements) that the
    # selected PHP lacks. Empty list when nothing is required, nothing is
    # missing, or the lists cannot be determined.
    my ( $user, $approot ) = @_;
    my $required = _app_required_extensions($approot);
    return [] unless ref $required eq 'ARRAY' && @{$required};
    my ( $php_bin, undef, undef ) = _select_php_for_app( $user, $approot );
    return [] unless defined $php_bin;
    my $missing = _php_missing_extensions( $php_bin, $approot, $required );
    return ref $missing eq 'ARRAY' ? $missing : [];
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_readiness - Read-only production readiness booleans.
#-------------------------------------------------------------------------------------------------
sub app_helper_readiness {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my $flags = _readiness_flags( $user, $home, $uid, $approot );
    $result->data( { user => $user, app => $app_param, %{$flags} } );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_production_preview / _apply / _undo - The only .env write:
#   exactly APP_ENV=production + APP_DEBUG=false. Responses never carry any
#   .env value except APP_ENV/APP_DEBUG themselves: the preview is a
#   structured changes list built server-side from those two keys, never
#   diff text.
#-------------------------------------------------------------------------------------------------
sub app_helper_production_preview {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ( $content, $err ) = _read_dotenv_file( $home, $uid, $approot );
    if ( !defined $content ) {
        $result->error( 'Cannot preview: [_1].', $err );
        return;
    }
    # The preview is built here from the TWO keys only and never carries
    # diff text — a line-based diff would echo every unchanged value that
    # sits between the changed lines (APP_KEY, DB_PASSWORD, MAIL_PASSWORD…)
    # straight into the response. Only APP_ENV and APP_DEBUG values may
    # appear, under their own keys.
    my $wanted = { APP_ENV => 'production', APP_DEBUG => 'false' };
    my %cur;
    for my $rec ( @{ _parse_dotenv_lines($content) } ) {
        if ( $rec->{type} eq 'kv' && exists $wanted->{ $rec->{key} } && !exists $cur{ $rec->{key} } ) {
            $cur{ $rec->{key} } = $rec->{value};
        }
    }
    my @changes;
    for my $k ( 'APP_ENV', 'APP_DEBUG' ) {
        my $from = $cur{$k};
        if ( !defined $from || $from ne $wanted->{$k} ) {
            push @changes, { key => $k, from => defined $from ? $from : '', to => $wanted->{$k} };
        }
    }
    $result->data(
        {
            user => $user, app => $app_param,
            changes  => \@changes,
            unchanged => @changes ? 0 : 1,
        }
    );
    return 1;
}

sub app_helper_production_apply {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ( $content, $err ) = _read_dotenv_file( $home, $uid, $approot );
    if ( !defined $content ) {
        $result->error( 'Cannot apply: [_1].', $err );
        return;
    }
    my ($rel) = _app_rel( $home, $approot );
    my $path  = "$approot/.env";
    # Preserve first: rolling backup + never-pruned original.
    my $files = _read_env_orig_journal($home);
    if ( !exists $files->{$rel} ) {
        my $orig = "$path.usertools-orig";
        if ( !_write_text_file( $orig, $content, 0600 ) ) {
            $result->error('Could not preserve the original .env; nothing was changed.');
            return;
        }
        $files->{$rel} = { orig => $orig };
        if ( !_write_env_orig_journal( $home, $files ) ) {
            unlink $orig;
            $result->error('Could not preserve the original .env; nothing was changed.');
            return;
        }
    }
    my $bak = _env_backup($path);
    my $wanted = { APP_ENV => 'production', APP_DEBUG => 'false' };
    my $new = _dotenv_set_keys( _parse_dotenv_lines($content), $wanted );
    if ( !_write_text_file( $path, $new, 0600 ) ) {
        $result->error('Could not write .env.');
        return;
    }
    chmod 0600, $path;
    my $clear = _artisan_fixed( $user, $home, $approot, ['config:clear'] );
    my $cache = _artisan_fixed( $user, $home, $approot, ['config:cache'] );
    my $flags = _readiness_flags( $user, $home, $uid, $approot );
    _activity_log( $home, 'app_helper', 'apply production env',
        { app => $app_param },
        { fn => 'app_helper_production_undo', args => { app => $app_param } } );
    $result->data(
        {
            user => $user, app => $app_param, backup => $bak,
            config_clear => { ok => $clear->{ok} ? 1 : 0 },
            config_cache => { ok => $cache->{ok} ? 1 : 0 },
            %{$flags},
        }
    );
    return 1;
}

sub app_helper_production_undo {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my ($rel) = _app_rel( $home, $approot );
    my $files = _read_env_orig_journal($home);
    my $entry = $files->{$rel};
    if ( !defined $entry || ref $entry ne 'HASH' || !defined $entry->{orig} ) {
        $result->error('Nothing to undo: no preserved original for this app.');
        return;
    }
    my $orig = $entry->{orig};
    if ( !-f $orig ) {
        $result->error('The preserved original is gone; ask your host.');
        return;
    }
    my $content = eval { _read_text_file($orig) };
    if ( $@ || !defined $content ) {
        $result->error('The preserved original cannot be read; ask your host.');
        return;
    }
    if ( !_write_text_file( "$approot/.env", $content, 0600 ) ) {
        $result->error('Could not restore .env.');
        return;
    }
    chmod 0600, "$approot/.env";
    delete $files->{$rel};
    _write_env_orig_journal( $home, $files );
    my $clear = _artisan_fixed( $user, $home, $approot, ['config:clear'] );
    $result->data(
        {
            user => $user, app => $app_param, restored => 1,
            config_clear => { ok => $clear->{ok} ? 1 : 0 },
        }
    );
    _activity_log( $home, 'app_helper', 'undo production env',
        { app => $app_param }, undef );
    return 1;
}

#-------------------------------------------------------------------------------------------------
# Name:
#   app_helper_key_generate - key:generate --force, only when APP_KEY is empty.
#-------------------------------------------------------------------------------------------------
sub app_helper_key_generate {
    my ( $args, $result ) = @_;

    return unless _gate_app( $result, $FEATURE_APP_HELPER );
    my ( $user, $uid, $home ) = _gate_caller($result);
    return unless defined $user;

    my ($app_param) = $args->get('app');
    my ( $approot, $app_err ) = _resolve_app( $home, $app_param );
    if ( !defined $approot ) {
        $result->error( 'Invalid app: [_1].', $app_err );
        return;
    }
    my $pairs = _read_dotenv_pairs("$approot/.env");
    if ( !defined $pairs ) {
        $result->error( 'Cannot read .env: [_1].', 'unreadable' );
        return;
    }
    if ( defined $pairs->{APP_KEY} && $pairs->{APP_KEY} ne '' ) {
        $result->error( 'Invalid request: [_1].', 'APP_KEY is already set' );
        return;
    }
    my $run = _artisan_fixed( $user, $home, $approot, [ 'key:generate', '--force' ] );
    if ( $run->{error} || !$run->{ok} ) {
        $result->error( 'Key generation failed: [_1].', $run->{error} // $run->{detail} // 'artisan failed' );
        return;
    }
    my $after = _read_dotenv_pairs("$approot/.env");
    my $set = ( defined $after && defined $after->{APP_KEY} && $after->{APP_KEY} ne '' ) ? 1 : 0;
    $result->data( { user => $user, app => $app_param, key_set => $set } );
    _activity_log( $home, 'app_helper', 'generate app key',
        { app => $app_param, key_set => $set }, undef );
    return 1;
}

1;
