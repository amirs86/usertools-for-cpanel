# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for whm/cgi/addon_usertools_settings.cgi, runnable
# WITHOUT a cPanel server:  prove -Itests/lib tests/test_whm_settings.t
#
# Technique: require the CGI (main() does not run under require), drive the
# pure backend (validate/write/read/audit/update/feature-help) against a
# File::Temp tree, and render the real template with stock Template Toolkit.
use strict;
use warnings;
use Test::More;
use FindBin;
use File::Temp qw(tempdir);

use lib "$FindBin::Bin/lib";

require "$FindBin::Bin/../whm/cgi/addon_usertools_settings.cgi";

my $Pkg = 'UserTools::WHM::Settings';

sub write_pair {
    my ($dir) = @_;
    open my $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "# sample\nssh_port=2222\nenable_shell=1\n";
    close $cf;
    open my $pf, '>', "$dir/usertools.private.conf" or die $!;
    print $pf "normal_shell_users=\n";
    close $pf;
    return;
}

# --- validation ------------------------------------------------------------------
{
    my $pdir = tempdir( CLEANUP => 1 );
    open my $l1, '>', "$pdir/webapp" or die $!;
    close $l1;
    open my $l2, '>', "$pdir/p1" or die $!;
    close $l2;
    open my $l3, '>', "$pdir/reseller_gold" or die $!;
    close $l3;
    my ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        {
            enable_shell => '1', allowed_shell_modes => 'disabled,jailed',
            enable_fix_home => '0', enable_bulk_perms => '1',
            enable_ownership_report => '1', enable_app_helper => '1',
            enable_space_cleaner => '0', cleaner_log_min_mb => '50',
            cleaner_trash_days => '7',
            allow_user_app_docroot => '0', app_packages => 'webapp, p1',
            max_job_seconds => '3600', enable_update_check => '0',
            update_repo => '', normal_shell_users => 'alice,bob',
            auto_update => '0', auto_update_scope => 'patch',
            ssh_port => '9999', bogus_key => 'x',
            composer_path => '/usr/local/bin/composer',
        },
        $pdir
    );
    is_deeply( $errs, [], 'valid input passes' );
    is( $clean->{enable_space_cleaner}, '0', 'space switch kept' );
    is( $clean->{cleaner_log_min_mb},  '50', 'log floor kept' );
    is( $clean->{cleaner_trash_days},  '7', 'trash days kept' );
    is( $clean->{app_packages}, 'webapp,p1', 'lists normalized' );
    is( $clean->{normal_shell_users}, 'alice,bob', 'user list kept' );
    is( $clean->{composer_path}, '/usr/local/bin/composer', 'absolute composer path kept' );
    ok( !exists $clean->{ssh_port}, 'read-only keys never written' );
    ok( !exists $clean->{bogus_key}, 'unknown keys never written' );

    # composer_path accepts empty (auto-discover) or an absolute path.
    my %base = (
        enable_shell => '1', allowed_shell_modes => 'disabled,jailed',
        enable_fix_home => '1', enable_bulk_perms => '1',
        enable_ownership_report => '1', enable_app_helper => '1',
        enable_space_cleaner => '0', cleaner_log_min_mb => '50',
        cleaner_trash_days => '7',
        allow_user_app_docroot => '0', app_packages => '',
        max_job_seconds => '3600', enable_update_check => '0',
        update_repo => '', normal_shell_users => '',
        auto_update => '0', auto_update_scope => 'patch',
    );
    ( $clean, $errs ) = $Pkg->can('validate_settings')->( { %base, composer_path => '' }, $pdir );
    is_deeply( $errs, [], 'empty composer_path accepted (auto-discover)' );
    is( $clean->{composer_path}, '', 'empty composer_path kept' );
    ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        { %base, composer_path => '/opt/tools/composer' }, $pdir );
    is_deeply( $errs, [], 'absolute composer_path accepted' );
    is( $clean->{composer_path}, '/opt/tools/composer', 'absolute composer_path kept' );
    # composer_lift_disable_functions is a strict bool, default 0.
    ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        { %base, composer_path => '', composer_lift_disable_functions => '1' }, $pdir );
    is_deeply( $errs, [], 'lift=1 accepted (explicit admin choice)' );
    is( $clean->{composer_lift_disable_functions}, '1', 'lift kept' );
    ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        { %base, composer_path => '', composer_lift_disable_functions => '2' }, $pdir );
    ok( ( grep { /composer_lift_disable_functions/ } @$errs ) ? 1 : 0, 'lift=2 refused' );
    for my $bad ( 'relative/bin/composer', '/has space/composer', '/x#y', '/x;y', 'com poser' ) {
        ( $clean, $errs ) = $Pkg->can('validate_settings')->( { %base, composer_path => $bad }, $pdir );
        ok( ( grep { /composer_path/ } @$errs ) ? 1 : 0, "composer_path refused: [$bad]" );
        ok( !exists $clean->{composer_path}, "bad composer_path never written: [$bad]" );
    }

    ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        {
            enable_shell => '2', allowed_shell_modes => 'turbo,,',
            enable_fix_home => '1', enable_bulk_perms => '1',
            enable_ownership_report => '1', enable_app_helper => '1',
            enable_space_cleaner => '1', cleaner_log_min_mb => '0',
            cleaner_trash_days => '91',
            allow_user_app_docroot => '0', app_packages => 'ok,bad user!',
            max_job_seconds => '30', enable_update_check => '0',
            update_repo => 'not a repo', normal_shell_users => 'root!',
            composer_path => 'not/absolute',
        },
        $pdir
    );
    ok( @$errs >= 5, 'every bad kind reported' );
    ok( ( grep { /enable_shell/ } @$errs ) ? 1 : 0, 'bad boolean reported' );
    ok( ( grep { /allowed_shell_modes/ } @$errs ) ? 1 : 0, 'bad enum reported' );
    ok( ( grep { /app_packages/ } @$errs ) ? 1 : 0, 'bad package reported' );
    ok( ( grep { /max_job_seconds/ } @$errs ) ? 1 : 0, 'bad seconds reported' );
    ok( ( grep { /update_repo/ } @$errs ) ? 1 : 0, 'bad repo reported' );
    ok( ( grep { /normal_shell_users/ } @$errs ) ? 1 : 0, 'bad username reported' );
    ok( ( grep { /composer_path/ } @$errs ) ? 1 : 0, 'bad path reported' );
    ok( ( grep { /cleaner_log_min_mb/ } @$errs ) ? 1 : 0, 'bad log floor reported' );
    ok( ( grep { /cleaner_trash_days/ } @$errs ) ? 1 : 0, 'bad trash days reported' );
    ok( !exists $clean->{cleaner_log_min_mb}, 'bad log floor never written' );
    ok( !exists $clean->{cleaner_trash_days}, 'bad trash days never written' );

    # Packages are validated against the existing package files.
    ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        {
            enable_shell => '1', allowed_shell_modes => 'disabled,jailed',
            enable_fix_home => '1', enable_bulk_perms => '1',
            enable_ownership_report => '1', enable_app_helper => '1',
            enable_space_cleaner => '0', cleaner_log_min_mb => '50',
            cleaner_trash_days => '7',
            allow_user_app_docroot => '0', app_packages => 'reseller_gold',
            max_job_seconds => '3600', enable_update_check => '0',
            update_repo => '', normal_shell_users => '',
            auto_update => '0', auto_update_scope => 'patch',
        },
        $pdir
    );
    is_deeply( $errs, [], 'reseller-prefixed package accepted' );

    for my $bad ( 'a/b', 'a=b', "a\nb", 'ghost' ) {
        ( $clean, $errs ) = $Pkg->can('validate_settings')->(
            {
                enable_shell => '1', allowed_shell_modes => 'disabled,jailed',
                enable_fix_home => '1', enable_bulk_perms => '1',
                enable_ownership_report => '1', enable_app_helper => '1',
                allow_user_app_docroot => '0', app_packages => $bad,
                max_job_seconds => '3600', enable_update_check => '0',
                update_repo => '', normal_shell_users => '',
            },
            $pdir
        );
        ok( @$errs ? 1 : 0, "package refused: [$bad]" );
    }
}

# --- write + read round-trip -------------------------------------------------------
{
    my $dir = tempdir( CLEANUP => 1 );
    write_pair($dir);
    open my $lf, '>', "$dir/webapp" or die $!;
    close $lf;
    my ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        {
            enable_shell => '0', allowed_shell_modes => 'disabled,jailed,normal',
            enable_fix_home => '1', enable_bulk_perms => '1',
            enable_ownership_report => '1', enable_app_helper => '1',
            enable_space_cleaner => '0', cleaner_log_min_mb => '50',
            cleaner_trash_days => '7',
            allow_user_app_docroot => '1', app_packages => 'webapp',
            max_job_seconds => '7200', enable_update_check => '1',
            update_repo => 'someone/usertools-for-cpanel', normal_shell_users => 'alice',
            auto_update => '1', auto_update_scope => 'minor',
            composer_path => '/usr/local/bin/composer',
        },
        $dir
    );
    is_deeply( $errs, [], 'valid input passes' );
    ok( $Pkg->can('write_settings')->( "$dir/usertools.conf", "$dir/usertools.private.conf", $clean ),
        'write accepted' );
    is( ( stat("$dir/usertools.conf") )[2] & 07777, 0644, 'public conf is 0644' );
    is( ( stat("$dir/usertools.private.conf") )[2] & 07777, 0600, 'private conf is 0600' );
    open my $cf, '<', "$dir/usertools.conf" or die $!;
    my $pub = do { local $/; <$cf> };
    close $cf;
    like( $pub, qr/^# sample$/m, 'comments preserved' );
    like( $pub, qr/^ssh_port=2222$/m, 'unmanaged keys preserved' );
    like( $pub, qr/^enable_shell=0$/m, 'value replaced' );
    unlike( $pub, qr/alice/, 'no names leak to the public file' );
    open my $pf, '<', "$dir/usertools.private.conf" or die $!;
    my $priv = do { local $/; <$pf> };
    close $pf;
    like( $priv, qr/^normal_shell_users=alice$/m, 'names only in the private file' );

    my $read = $Pkg->can('read_settings')->( "$dir/usertools.conf", "$dir/usertools.private.conf" );
    is( $read->{enable_shell}, '0', 'read back' );
    is( $read->{normal_shell_users}, 'alice', 'private read back' );
    is( $read->{ssh_port}, '2222', 'port read back' );
    is( $read->{composer_path}, '/usr/local/bin/composer', 'composer_path round-trips' );

    my $defaults = $Pkg->can('read_settings')->( "$dir/missing.conf", "$dir/missing.private" );
    is( $defaults->{composer_path}, '', 'composer_path defaults to empty' );
}

# --- Composer discovery (same order as the user-side code) ----------------------
{
    my $dir = tempdir( CLEANUP => 1 );
    local @UserTools::WHM::Settings::COMPOSER_DEFAULT_PATHS =
      ( '/usr/local/bin/composer', '/opt/cpanel/composer/bin/composer' );

    # Candidate order: admin path first, then the two defaults, labelled.
    open my $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "composer_path=/custom/composer\n";
    close $cf;
    my @cands = $Pkg->can('composer_candidates')->("$dir/usertools.conf");
    is( scalar @cands, 3, 'exactly the three locations' );
    is( $cands[0][0], '/custom/composer', 'admin composer_path first' );
    is( $cands[0][1], 'composer_path (admin setting)', 'admin source labelled' );
    is( $cands[1][0], '/usr/local/bin/composer', 'getcomposer.org location second' );
    is( $cands[1][1], 'getcomposer.org global install', 'default source labelled' );
    is( $cands[2][0], '/opt/cpanel/composer/bin/composer', 'fallback last' );

    # Injected ownership check: found at the admin path, with its source.
    my $got = $Pkg->can('find_composer')->(
        "$dir/usertools.conf",
        sub { return $_[0] eq '/custom/composer' ? ( 'ok', undef ) : ( 'missing', 'not found' ); }
    );
    is_deeply(
        $got,
        { found => 1, path => '/custom/composer', source => 'composer_path (admin setting)' },
        'configured composer reported with its source'
    );

    # An UNSAFE admin path stops the search: the default behind it is not
    # silently used instead — the page shows the offending path.
    $got = $Pkg->can('find_composer')->(
        "$dir/usertools.conf",
        sub {
            return $_[0] eq '/custom/composer'
              ? ( 'unsafe', 'not root-owned or writable by group/others' )
              : ( 'ok', undef );
        }
    );
    is( $got->{found}, 0, 'unsafe configured composer not reported as found' );
    is( $got->{path}, '/custom/composer', 'the offending path is shown' );
    like( $got->{reason}, qr/root-owned/, 'reason explains the ownership rule' );

    # No admin path → the first default location is what the page reports.
    open $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "enable_shell=1\n";
    close $cf;
    $got = $Pkg->can('find_composer')->(
        "$dir/usertools.conf",
        sub { return $_[0] eq '/usr/local/bin/composer' ? ( 'ok', undef ) : ( 'missing', 'not found' ); }
    );
    is( $got->{found}, 1, 'default location found' );
    is( $got->{path}, '/usr/local/bin/composer', 'default path reported' );
    is( $got->{source}, 'getcomposer.org global install', 'default labelled' );

    # Nothing anywhere → found=0 with the "none" reason for the template.
    $got = $Pkg->can('find_composer')->( "$dir/usertools.conf", sub { return ( 'missing', 'not found' ); } );
    is_deeply( $got, { found => 0, reason => 'no composer binary found' },
        'none found reported' );

    # The REAL ownership check (no fakes): absent stays missing; a file
    # owned by the test user is refused as not root-owned.
    my ( $state, $why ) = $Pkg->can('_composer_bin_check')->("$dir/definitely-missing");
    is( $state, 'missing', 'real check: absent binary is missing' );
    open my $bf, '>', "$dir/composer" or die $!;
    print $bf "#!/bin/sh\nexit 0\n";
    close $bf;
    chmod 0755, "$dir/composer";
    ( $state, $why ) = $Pkg->can('_composer_bin_check')->("$dir/composer");
    is( $state, 'unsafe', 'real check: non-root-owned binary refused' );
    like( $why, qr/root-owned/, 'real check: reason states the rule' );

    open $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "composer_path=$dir/composer\n";
    close $cf;
    local @UserTools::WHM::Settings::COMPOSER_DEFAULT_PATHS = ( "$dir/nope1", "$dir/nope2" );
    $got = $Pkg->can('find_composer')->("$dir/usertools.conf");
    is( $got->{found}, 0, 'page reports the configured-but-unsafe composer' );
    is( $got->{path}, "$dir/composer", 'with its path' );
    like( $got->{reason}, qr/root-owned/, 'with the ownership reason' );
}

# --- CageFS composer visibility (WHM row) --------------------------------------
{
    require File::Path;
    my $dir = tempdir( CLEANUP => 1 );
    local @UserTools::WHM::Settings::COMPOSER_DEFAULT_PATHS = ('/usr/local/bin/composer');
    open my $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "enable_shell=1\n";
    close $cf;
    my $mp = "$dir/cagefs.mp";
    open my $mf, '>', $mp or die $!;
    print $mf "# cagefs\n";
    close $mf;
    my $confd = "$dir/conf.d";
    File::Path::make_path($confd);
    local $UserTools::WHM::Settings::CAGEFS_MP = $mp;
    local $UserTools::WHM::Settings::CAGEFS_CONF_D = $confd;
    my $got = $Pkg->can('find_composer')->(
        "$dir/usertools.conf",
        sub { return $_[0] eq '/usr/local/bin/composer' ? ( 'ok', undef ) : ( 'missing', 'not found' ); }
    );
    is( $got->{found}, 0, 'unmounted composer not found on the WHM page' );
    like( $got->{reason}, qr/not visible to caged users/, 'WHM row names cage visibility' );
    is( $got->{cagefs}, 1, 'WHM flags the cage case for the template' );
    open my $ef, '>', "$confd/usertools-composer.cfg" or die $!;
    print $ef "[usertools-composer]\ncomment=Composer\npaths=/usr/local/bin/composer\n";
    close $ef;
    $got = $Pkg->can('find_composer')->(
        "$dir/usertools.conf",
        sub { return $_[0] eq '/usr/local/bin/composer' ? ( 'ok', undef ) : ( 'missing', 'not found' ); }
    );
    is( $got->{found}, 1, 'conf.d-listed composer found again' );
}

# --- audit tail ----------------------------------------------------------------------
{
    my $dir = tempdir( CLEANUP => 1 );
    open my $lf, '>', "$dir/audit.log" or die $!;
    print $lf "line$_\n" for 1 .. 250;
    close $lf;
    my $tail = $Pkg->can('audit_tail')->( "$dir/audit.log", 200 );
    is( scalar(@$tail), 200, 'last 200 lines' );
    is( $tail->[0],  'line51',  'window starts right' );
    is( $tail->[-1], 'line250', 'window ends right' );
    is_deeply( $Pkg->can('audit_tail')->( "$dir/missing", 200 ), [], 'missing log is empty' );
}

# --- update check (mocked fetch, no network) -------------------------------------------
{
    my $r = $Pkg->can('update_check')->(
        '0.1.0', 'someone/usertools-for-cpanel',
        sub { return { tag_name => 'v0.2.0', html_url => 'https://example.invalid/r' }; } );
    is( $r->{latest}, 'v0.2.0', 'latest parsed' );
    is( $r->{update_available}, 1, 'newer release reported' );

    $r = $Pkg->can('update_check')->(
        '0.2.0', 'someone/usertools-for-cpanel',
        sub { return { tag_name => 'v0.2.0' }; } );
    is( $r->{update_available}, 0, 'current release is up to date' );

    $r = $Pkg->can('update_check')->( '0.1.0', '', sub { die 'must not fetch'; } );
    like( $r->{error}, qr/update_repo/, 'empty repo refused without fetching' );

    $r = $Pkg->can('update_check')->( '0.1.0', 'someone/usertools-for-cpanel', sub { die 'down'; } );
    like( $r->{error}, qr/failed/, 'fetch failure reported, never fatal' );
}

# --- feature-list help (no silent changes) -----------------------------------------------
{
    use File::Path qw(make_path);
    my $dir = tempdir( CLEANUP => 1 );
    make_path("$dir/features");
    open my $ff, '>', "$dir/features/default" or die $!;
    close $ff;
    my $help = \&UserTools::WHM::Settings::feature_list_help;
    my $h = $help->( 'default', 'usertools_shell', "$dir/features" );
    like( $h->{steps}, qr/usertools_shell/, 'steps name the feature' );
    like( $h->{steps}, qr/Feature Manager/, 'steps name the WHM path' );
    $h = $help->( '../x', 'usertools_shell', "$dir/features" );
    like( $h->{error}, qr/Invalid/, 'traversal refused' );
    $h = $help->( '..', 'usertools_shell', "$dir/features" );
    like( $h->{error}, qr/Invalid/, 'dot-only refused' );
    $h = $help->( 'nope', 'usertools_shell', "$dir/features" );
    like( $h->{error}, qr/does not exist/, 'missing list reported' );
}

# --- template renders ----------------------------------------------------------------------
{
    require Template;
    my $tt = Template->new( { ENCODING => 'utf8', INCLUDE_PATH => ["$FindBin::Bin/../whm/views", "$FindBin::Bin/tt_whm"] } );
    my $out = '';
    my $ok = $tt->process(
        'settings.tt',
        {
            settings => { enable_shell => '1', allowed_shell_modes => 'disabled,jailed',
                enable_fix_home => '1', enable_bulk_perms => '1',
                enable_ownership_report => '1', enable_app_helper => '1',
                enable_space_cleaner => '1', cleaner_log_min_mb => '50',
                cleaner_trash_days => '7',
                allow_user_app_docroot => '0', app_packages => '',
                max_job_seconds => '3600', enable_update_check => '0',
                update_repo => '', normal_shell_users => '', ssh_port => '2222',
                composer_path => '/usr/local/bin/composer' },
            errors  => ['demo problem'],
            message => 'Saved.',
            audit   => [ '2026-01-01T00:00:00Z uttest disabled->jailed', 'second <line>' ],
            version => '0.1.0-dev',
            update  => { latest => 'v0.2.0', url => 'https://example.invalid', update_available => 1 },
            token   => 'abc123',
            composer => { found => 1, path => '/usr/local/bin/composer',
                source => 'getcomposer.org global install' },
        },
        \$out
    );
    ok( $ok, 'template processes' ) or diag( $tt->error() );
    like( $out, qr/UserTools Settings/, 'title rendered' );
    like( $out, qr/demo problem/, 'errors rendered' );
    open my $tfh, '<', "$FindBin::Bin/../whm/views/settings.tt" or die $!;
    my $tsrc = do { local $/; <$tfh> };
    close $tfh;
    like( $tsrc, qr/\[% WRAPPER 'master_templates\/master\.tmpl'/, 'WHM master WRAPPER' );
    unlike( $out, qr/<html/i, 'no own html tag in output' );
    like( $out, qr/table table-striped/, 'WHM table classes' );
    like( $out, qr/btn btn-primary/, 'WHM button classes' );
    like( $out, qr/Apache License/, 'licence footer kept' );
    like( $out, qr/second &lt;line&gt;/, 'audit escaped' );
    like( $out, qr/name="token" value="abc123"/, 'token echoed' );
    like( $out, qr/name="enable_space_cleaner"/, 'space switch field rendered' );
    like( $out, qr/name="cleaner_log_min_mb"[^>]*value="50"/, 'log floor field rendered' );
    like( $out, qr/name="cleaner_trash_days"[^>]*value="7"/, 'trash days field rendered' );
    like( $out, qr/usertools_space_cleaner/, 'space feature listed' );
    like( $out, qr/<form method="post" action="">/, 'forms post relatively (token stays in path)' );
    unlike( $out, qr/<form[^>]*action="https?:/, 'no absolute form targets' );

    # Composer found → path + source shown, install hint hidden, and
    # the admin path field rendered with its value.
    like( $out, qr{Found: <code>/usr/local/bin/composer</code>}, 'found composer path shown' );
    like( $out, qr/getcomposer\.org global install/, 'discovery source shown' );
    like( $out, qr/name="composer_path"[^>]*value="\/usr\/local\/bin\/composer"/,
        'composer_path field rendered' );
    unlike( $out, qr/getcomposer\.org\/installer/, 'install hint hidden when found' );

    # Not found → "none" + the install command and the setting hint.
    my $none = '';
    $ok = $tt->process(
        'settings.tt',
        {
            settings => { enable_shell => '1', composer_path => '' },
            errors => [], message => '', audit => [], version => '0.1.0-dev', token => 't',
            composer => { found => 0, reason => 'no composer binary found' },
        },
        \$none
    );
    ok( $ok, 'not-found variant processes' ) or diag( $tt->error() );
    like( $none, qr{<strong>None found\.</strong>}, '"none found" shown' );
    like( $none, qr{getcomposer\.org/installer}, 'install command shown' );
    like( $none, qr{--install-dir=/usr/local/bin --filename=composer}, 'exact install target shown' );
    like( $none, qr{composer_path}, 'hint points at the setting field' );

    # Configured but unsafe → path + reason shown.
    my $unsafe = '';
    $ok = $tt->process(
        'settings.tt',
        {
            settings => { enable_shell => '1', composer_path => '/custom/composer' },
            errors => [], message => '', audit => [], version => '0.1.0-dev', token => 't',
            composer => { found => 0, path => '/custom/composer',
                source => 'composer_path (admin setting)',
                reason => 'not root-owned or writable by group/others' },
        },
        \$unsafe
    );
    ok( $ok, 'unsafe variant processes' ) or diag( $tt->error() );
    like( $unsafe, qr{<strong>Not usable:</strong> <code>/custom/composer</code>},
        'unsafe path shown' );
    like( $unsafe, qr{not root-owned or writable by group/others}, 'unsafe reason shown' );
    like( $unsafe, qr{the search stops here}, 'page says the search stops there' );
}

# --- main() ACL gate ------------------------------------------------------------------------
{
    use File::Path qw(make_path);
    my $dir = tempdir( CLEANUP => 1 );
    open my $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "enable_shell=1\n";
    close $cf;
    open my $pf, '>', "$dir/usertools.private.conf" or die $!;
    print $pf "normal_shell_users=\n";
    close $pf;
    local $UserTools::WHM::Settings::CONF         = "$dir/usertools.conf";
    local $UserTools::WHM::Settings::PRIVATE_CONF = "$dir/usertools.private.conf";
    local $UserTools::WHM::Settings::AUDIT_LOG    = "$dir/audit.log";
    local $UserTools::WHM::Settings::VERSION_FILE = "$dir/VERSION";
    local $ENV{USERTOOLS_WHM_TEMPLATE} = "$FindBin::Bin/../whm/views/settings.tt";
    local $UserTools::WHM::Settings::ACL_CHECK = sub { return ( 0, 'Access denied: root only.' ); };
    local $ENV{USERTOOLS_TEST_MODE} = '1';

    my $run_main = sub {
        my (%opt) = @_;
        local $ENV{REQUEST_METHOD} = $opt{method} // 'GET';
        local $ENV{QUERY_STRING}   = $opt{query} // '';
        my $out = '';
        open my $cap, '>', \$out or die $!;
        local *STDOUT = $cap;
        if ( ( $opt{method} // 'GET' ) eq 'POST' ) {
            my $body = $opt{body} // '';
            local $ENV{CONTENT_TYPE}   = 'application/x-www-form-urlencoded';
            local $ENV{CONTENT_LENGTH} = length($body);
            open my $in, '<', \$body or die $!;
            local *STDIN = $in;
            UserTools::WHM::Settings::main();
        }
        else {
            delete local $ENV{CONTENT_TYPE};
            delete local $ENV{CONTENT_LENGTH};
            UserTools::WHM::Settings::main();
        }
        close $cap;
        return $out;
    };

    my $before_pub  = do { open my $fh, '<', "$dir/usertools.conf" or die $!; local $/; <$fh> };
    my $before_priv = do { open my $fh, '<', "$dir/usertools.private.conf" or die $!; local $/; <$fh> };

    my $out = $run_main->( method => 'GET' );
    like( $out, qr/403/, 'non-root GET refused' );
    $out = $run_main->( method => 'POST', body => 'action=save&enable_shell=0' );
    like( $out, qr/403/, 'non-root POST save refused' );
    $out = $run_main->( method => 'POST', body => 'action=check_updates' );
    like( $out, qr/403/, 'non-root update check refused' );
    $out = $run_main->( method => 'POST', body => 'action=feature_help&list=default&feature=usertools_shell' );
    like( $out, qr/403/, 'non-root feature help refused' );

    my $after_pub  = do { open my $fh, '<', "$dir/usertools.conf" or die $!; local $/; <$fh> };
    my $after_priv = do { open my $fh, '<', "$dir/usertools.private.conf" or die $!; local $/; <$fh> };
    is( $after_pub,  $before_pub,  'refusals read nothing writable: public untouched' );
    is( $after_priv, $before_priv, 'refusals read nothing writable: private untouched' );
    ok( !-e "$dir/audit.log", 'no audit file created by refusals' );

    local $UserTools::WHM::Settings::ACL_CHECK = sub { return ( 1, undef ); };
    {
        # Fake WHM templating: record the process_template call.
        no warnings 'redefine';
        local $INC{'Cpanel/Template.pm'} = 'fake';
        local *Cpanel::Template::process_template = sub {
            push @FakeTemplate::CALLS, [@_];
            return 1;
        };
        @FakeTemplate::CALLS = ();
        $out = $run_main->( method => 'GET' );
        is( scalar(@FakeTemplate::CALLS), 1, 'root GET renders through process_template' );
        is( $FakeTemplate::CALLS[0][0], 'whostmgr', 'whostmgr app' );
        is( $FakeTemplate::CALLS[0][1]{template_file}, $ENV{USERTOOLS_WHM_TEMPLATE},
            'configured template path passed through' );
        delete local $ENV{USERTOOLS_WHM_TEMPLATE};
        @FakeTemplate::CALLS = ();
        $out = $run_main->( method => 'GET' );
        is( $FakeTemplate::CALLS[0][1]{template_file}, '/usr/local/cpanel/whostmgr/docroot/addon/usertools/settings.tt',
            'default template path' );
        is( $FakeTemplate::CALLS[0][1]{print}, 1, 'print flag' );
        ok( exists $FakeTemplate::CALLS[0][1]{settings}, 'vars travel along' );
        ok( exists $FakeTemplate::CALLS[0][1]{composer}, 'composer discovery travels along' );
        ok( defined $FakeTemplate::CALLS[0][1]{composer}{found},
            'discovery result has a found flag' );
    }
    $out = $run_main->( method => 'GET' );
    like( $out, qr/Template error/, 'missing template engine falls back to plain text' );
    open my $lfh, '<', "$dir/audit.log" or die "no error log: $!";
    my $logged = do { local $/; <$lfh> };
    close $lfh;
    like( $logged, qr/template error/, 'detail logged, not shown' );
    {
        # With templating present, the save-over-GET refusal reaches the page vars.
        no warnings 'redefine';
        local $INC{'Cpanel/Template.pm'} = 'fake';
        local *Cpanel::Template::process_template = sub {
            push @FakeTemplate::CALLS, [@_];
            return 1;
        };
        @FakeTemplate::CALLS = ();
        $out = $run_main->( method => 'GET', query => 'action=save&enable_shell=0' );
        my ($vars) = map { $_->[1] } @FakeTemplate::CALLS;
        ok( ( grep { /Save requires POST/ } @{ $vars->{errors} } ) ? 1 : 0,
            'save over GET refused' );
    }
    $after_pub = do { open my $fh, '<', "$dir/usertools.conf" or die $!; local $/; <$fh> };
    is( $after_pub, $before_pub, 'GET save writes nothing' );
}

# --- auto_update scope validation ----------------------------------------------------
{
    my $pdir = tempdir( CLEANUP => 1 );
    my %good = (
        enable_shell => '1', allowed_shell_modes => 'disabled,jailed',
        enable_fix_home => '1', enable_bulk_perms => '1',
        enable_ownership_report => '1', enable_app_helper => '1',
        enable_space_cleaner => '0', cleaner_log_min_mb => '50',
        cleaner_trash_days => '7',
        allow_user_app_docroot => '0', app_packages => '',
        max_job_seconds => '3600', enable_update_check => '0',
        update_repo => '', normal_shell_users => '',
        auto_update => '1', auto_update_scope => 'minor',
        composer_path => '',
    );
    my ( $clean, $errs ) = $Pkg->can('validate_settings')->( \%good, $pdir );
    is_deeply( $errs, [], 'auto_update scope minor accepted' );
    is( $clean->{auto_update_scope}, 'minor', 'scope kept' );
    ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        { %good, auto_update_scope => 'weekly' }, $pdir );
    ok( ( grep { /auto_update_scope/ } @$errs ) ? 1 : 0, 'bad scope refused' );
    ( $clean, $errs ) = $Pkg->can('validate_settings')->(
        { %good, auto_update => '2' }, $pdir );
    ok( ( grep { /auto_update/ } @$errs ) ? 1 : 0, 'bad auto_update refused' );
}

# --- Jailed-shell tweak readiness ----------------------------------------------------
{
    my $dir = tempdir( CLEANUP => 1 );
    open my $of, '>', "$dir/off.conf" or die $!;
    print $of "jaildefaultshell=0\n";
    close $of;
    is( $Pkg->can('jail_default_on')->("$dir/off.conf"), 0, 'explicit off reads 0' );
    open my $nf, '>', "$dir/on.conf" or die $!;
    print $nf "# comment\njaildefaultshell = 1\n";
    close $nf;
    is( $Pkg->can('jail_default_on')->("$dir/on.conf"), 1, 'on reads 1' );
    open my $kf, '>', "$dir/nokey.conf" or die $!;
    print $kf "otherkey=1\n";
    close $kf;
    is( $Pkg->can('jail_default_on')->("$dir/nokey.conf"), undef, 'absent key is undef' );
    is( $Pkg->can('jail_default_on')->("$dir/missing.conf"), undef, 'missing file is undef' );
}

# --- read_auto_status ------------------------------------------------------------
{
    my $dir = tempdir( CLEANUP => 1 );
    is_deeply( $Pkg->can('read_auto_status')->("$dir/missing"), undef, 'missing status is undef' );
    open my $bf, '>', "$dir/broken" or die $!;
    print $bf "garbage without equals\n";
    close $bf;
    is_deeply( $Pkg->can('read_auto_status')->("$dir/broken"), undef, 'broken status is undef' );
    open my $gf, '>', "$dir/good" or die $!;
    print $gf "ok=0\nreason=scope block\nat=2026-10-29T00:00:00Z\n";
    close $gf;
    my $st = $Pkg->can('read_auto_status')->("$dir/good");
    is( $st->{ok}, '0', 'status ok parsed' );
    is( $st->{reason}, 'scope block', 'status reason parsed' );
}

# --- update_now runs the updater with the fixed action only -----------------------
{
    use File::Path qw(make_path);
    my $dir = tempdir( CLEANUP => 1 );
    open my $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "enable_shell=1\nenable_update_check=1\nupdate_repo=someone/usertools-for-cpanel\n";
    close $cf;
    open my $pf, '>', "$dir/usertools.private.conf" or die $!;
    print $pf "normal_shell_users=\n";
    close $pf;
    open my $uf, '>', "$dir/fake-updater" or die $!;
    print $uf "#!/bin/sh\nprintf '%s\\n' \"\$#:\$*\" >>\"$dir/argv.txt\"\necho 'updated to v0.2.0'\n";
    close $uf;
    chmod 0755, "$dir/fake-updater";
    local $UserTools::WHM::Settings::CONF         = "$dir/usertools.conf";
    local $UserTools::WHM::Settings::PRIVATE_CONF = "$dir/usertools.private.conf";
    local $UserTools::WHM::Settings::AUDIT_LOG    = "$dir/audit.log";
    local $UserTools::WHM::Settings::VERSION_FILE = "$dir/VERSION";
    local $UserTools::WHM::Settings::UPDATER      = "$dir/fake-updater";
    local $UserTools::WHM::Settings::ACL_CHECK = sub { return ( 1, undef ); };
    local $ENV{USERTOOLS_TEST_MODE} = '1';
    local $ENV{USERTOOLS_WHM_TEMPLATE} = "$FindBin::Bin/../whm/views/settings.tt";

    my $run_main = sub {
        my (%opt) = @_;
        local $ENV{REQUEST_METHOD} = $opt{method} // 'GET';
        local $ENV{QUERY_STRING}   = $opt{query} // '';
        my $out = '';
        open my $cap, '>', \$out or die $!;
        local *STDOUT = $cap;
        if ( ( $opt{method} // 'GET' ) eq 'POST' ) {
            my $body = $opt{body} // '';
            local $ENV{CONTENT_TYPE}   = 'application/x-www-form-urlencoded';
            local $ENV{CONTENT_LENGTH} = length($body);
            open my $in, '<', \$body or die $!;
            local *STDIN = $in;
            UserTools::WHM::Settings::main();
        }
        else {
            delete local $ENV{CONTENT_TYPE};
            delete local $ENV{CONTENT_LENGTH};
            UserTools::WHM::Settings::main();
        }
        close $cap;
        return $out;
    };

    # Fake WHM templating (as above): record process_template vars.
    {
        no warnings 'redefine';
        local $INC{'Cpanel/Template.pm'} = 'fake';
        local *Cpanel::Template::process_template = sub {
            push @FakeTemplate2::CALLS, [@_];
            return 1;
        };
        @FakeTemplate2::CALLS = ();
        $run_main->( method => 'POST', body => 'action=update_now' );
        my ($vars) = map { $_->[1] } @FakeTemplate2::CALLS;
        like( $vars->{message} // '', qr/updated to v0\.2\.0/, 'update_now runs and reports' );
        open my $af, '<', "$dir/argv.txt" or die "no updater argv: $!";
        my $argv = do { local $/; <$af> };
        close $af;
        is( $argv, "1:--update\n", 'updater gets the fixed action only' );

        @FakeTemplate2::CALLS = ();
        unlink "$dir/argv.txt";
        $run_main->( method => 'GET', query => 'action=update_now' );
        ($vars) = map { $_->[1] } @FakeTemplate2::CALLS;
        ok( ( grep { /Update requires POST/ } @{ $vars->{errors} } ) ? 1 : 0,
            'update_now over GET refused' );
        ok( !-e "$dir/argv.txt", 'refused GET runs nothing' );
    }

    # The updater child gets a clean environment (PATH only).
    {
        open my $ef, '>', "$dir/env-updater" or die $!;
        print $ef "#!/bin/sh\necho \"PATH=\$PATH\" >>\"$dir/env.txt\"\n"
          . "echo \"USERTOOLS_POLICY=\${USERTOOLS_POLICY-unset}\" >>\"$dir/env.txt\"\n"
          . "echo ok\n";
        close $ef;
        chmod 0755, "$dir/env-updater";
        local $UserTools::WHM::Settings::UPDATER = "$dir/env-updater";
        local $ENV{USERTOOLS_POLICY} = '/tmp/evil.conf';
        local $ENV{PATH} = "/tmp/evil:$ENV{PATH}";
        unlink "$dir/env.txt";
        my ( $msg, $err ) = $Pkg->can('run_updater')->();
        ok( !$err, 'clean-env updater runs' );
        open my $rf, '<', "$dir/env.txt" or die "no env capture: $!";
        my $env = do { local $/; <$rf> };
        close $rf;
        like( $env, qr/^PATH=\/usr\/local\/sbin:\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/sbin:\/bin$/m, 'child PATH is the fixed root PATH' );
        like( $env, qr/^USERTOOLS_POLICY=unset$/m, 'USERTOOLS_* never reaches the updater' );
    }
}

# --- Template override is a test seam only ----------------------------------
{
    local $ENV{USERTOOLS_TEST_MODE} = '1';
    local $ENV{USERTOOLS_WHM_TEMPLATE} = '/tmp/evil.tt';
    ok( $Pkg->can('_test_mode')->() == ( $> != 0 ? 1 : 0 ),
        'test mode reflects flag plus non-root' );
    delete local $ENV{USERTOOLS_TEST_MODE};
    is( $Pkg->can('_test_mode')->(), 0, 'template override off without the flag' );
}

# --- Cosign gate for updates ------------------------------------------------
{
    my $got = $Pkg->can('find_cosign')->( sub { return ( 'ok', undef ); } );
    is( $got->{found}, 1, 'cosign found' );
    $got = $Pkg->can('find_cosign')->( sub { return ( 'missing', 'not found' ); } );
    is( $got->{found}, 0, 'cosign missing reported' );
    my ( $state, $why ) = $Pkg->can('_cosign_bin_check')->('/definitely/missing');
    is( $state, 'missing', 'real check misses absent binary' );
    # Auto-update refuses without cosign.
    my $dir = tempdir( CLEANUP => 1 );
    open my $cf, '>', "$dir/usertools.conf" or die $!;
    print $cf "enable_shell=1\n";
    close $cf;
    open my $pf, '>', "$dir/usertools.private.conf" or die $!;
    print $pf "normal_shell_users=\n";
    close $pf;
    local $UserTools::WHM::Settings::CONF         = "$dir/usertools.conf";
    local $UserTools::WHM::Settings::PRIVATE_CONF = "$dir/usertools.private.conf";
    local $UserTools::WHM::Settings::ACL_CHECK = sub { return ( 1, undef ); };
    local $ENV{USERTOOLS_TEST_MODE} = '1';
    local $ENV{USERTOOLS_WHM_TEMPLATE} = "$FindBin::Bin/../whm/views/settings.tt";
    no warnings 'redefine';
    local *UserTools::WHM::Settings::find_cosign = sub { return { found => 0, reason => 'cosign not found' }; };
    {
        local $INC{'Cpanel/Template.pm'} = 'fake';
        local *Cpanel::Template::process_template = sub { push @FakeU::CALLS, [@_]; return 1; };
        @FakeU::CALLS = ();
        local $ENV{REQUEST_METHOD} = 'POST';
        local $ENV{CONTENT_LENGTH} = length('action=save&enable_shell=1&allowed_shell_modes=disabled%2Cjailed&enable_fix_home=1&enable_bulk_perms=1&enable_ownership_report=1&enable_app_helper=1&enable_space_cleaner=0&cleaner_log_min_mb=50&cleaner_trash_days=7&allow_user_app_docroot=0&app_packages=&max_job_seconds=3600&enable_update_check=0&update_repo=&auto_update=1&auto_update_scope=patch&composer_path=&composer_lift_disable_functions=0');
        open my $in, '<', \'action=save&enable_shell=1&allowed_shell_modes=disabled%2Cjailed&enable_fix_home=1&enable_bulk_perms=1&enable_ownership_report=1&enable_app_helper=1&enable_space_cleaner=0&cleaner_log_min_mb=50&cleaner_trash_days=7&allow_user_app_docroot=0&app_packages=&max_job_seconds=3600&enable_update_check=0&update_repo=&auto_update=1&auto_update_scope=patch&composer_path=&composer_lift_disable_functions=0' or die $!;
        local *STDIN = $in;
        my $out = '';
        open my $cap, '>', \$out or die $!;
        local *STDOUT = $cap;
        UserTools::WHM::Settings::main();
        close $cap;
        my ($vars) = map { $_->[1] } @FakeU::CALLS;
        ok( ( grep { /cosign/ } @{ $vars->{errors} } ) ? 1 : 0,
            'auto_update=1 refused without cosign' );
    }
}

# --- template renders update-now form + auto banner ---------------------------------
{
    require Template;
    my $tt = Template->new( { ENCODING => 'utf8', INCLUDE_PATH => ["$FindBin::Bin/../whm/views", "$FindBin::Bin/tt_whm"] } );
    my $out = '';
    my $ok = $tt->process(
        'settings.tt',
        {
            settings => { enable_shell => '1', composer_path => '', auto_update => '1', auto_update_scope => 'minor' },
            errors => [], message => '', audit => [], version => '0.1.0-dev', token => 't',
            composer => { found => 0, reason => 'x' },
            cosign => { found => 1, path => '/usr/local/bin/cosign' },
            update => { latest => 'v0.2.0', url => 'https://example.invalid',
                update_available => 1 },
            auto_status => { ok => '0', reason => 'scope block', at => '2026-10-29T00:00:00Z' },
        },
        \$out
    );
    ok( $ok, 'update template processes' ) or diag( $tt->error() );
    like( $out, qr/name="action" value="update_now"/, 'update-now button rendered when newer exists' );
    unlike( $out, qr/Update now<\/button>.*disabled|disabled.*Update now/,
        'button enabled when cosign found' );
    like( $out, qr/Last automatic update failed/, 'auto failure banner rendered' );
    like( $out, qr/scope block/, 'banner reason escaped into page' );
    like( $out, qr/name="auto_update"/, 'auto_update field rendered' );
    like( $out, qr/name="auto_update_scope"/, 'scope field rendered' );
    my $noc = '';
    $ok = $tt->process(
        'settings.tt',
        {
            settings => { enable_shell => '1' }, errors => [], message => '',
            audit => [], version => '0.1.0-dev', token => 't',
            composer => { found => 0, reason => 'x' },
            cosign => { found => 0, reason => 'cosign not found' },
            update => { latest => 'v0.2.0', url => 'https://example.invalid',
                update_available => 1 },
        },
        \$noc
    );
    ok( $ok, 'no-cosign template processes' ) or diag( $tt->error() );
    like( $noc, qr/Updates need cosign/, 'missing cosign state shown' );
    like( $noc, qr/cosign install docs/, 'install docs cited' );
    like( $noc, qr/disabled/, 'update button disabled without cosign' );
    my $none = '';
    $ok = $tt->process(
        'settings.tt',
        {
            settings => {}, errors => [], message => '', audit => [], version => '0.1.0-dev', token => 't',
            composer => { found => 0, reason => 'x' },
            update => { latest => 'v0.2.0', url => 'https://example.invalid',
                update_available => 0 },
        },
        \$none
    );
    ok( $ok, 'up-to-date template processes' ) or diag( $tt->error() );
    unlike( $none, qr/name="action" value="update_now"/, 'no update button when current' );
}

# --- AppConfig shape -------------------------------------------------------------------------
{
    # entryurl must not start with "cgi/" or "/" (WHM resolves it relative
    # to its cgi/ dir); url must start with "/" (docroot-relative, required).
    open my $fh, '<', "$FindBin::Bin/../whm/usertools.conf" or die $!;
    my ( $entryurl, $url );
    while ( my $line = <$fh> ) {
        if ( $line =~ /^entryurl=(.*)$/ ) {
            $entryurl = $1;
        }
        if ( $line =~ /^url=(.*)$/ ) {
            $url = $1;
        }
    }
    close $fh;
    ok( defined $entryurl, 'entryurl present' );
    unlike( $entryurl, qr{^(cgi/|/)}, 'entryurl has no cgi/ or / prefix' );
    like( $url, qr{^/}, 'url is docroot-relative' );
}

done_testing();
