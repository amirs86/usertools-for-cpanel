#!/usr/local/cpanel/3rdparty/bin/perl
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# UserTools Settings — WHM page backend + addon CGI.
#
# Shebang is cPanel's perl (Guide to WHM Plugins - Plugin Files: the doc
# examples use #!/usr/local/cpanel/3rdparty/bin/perl; no system perl exists
# for cpsrvd). Those examples carry no `use lib`, so neither do we: core
# modules only, plus Template at runtime via cpsrvd's own @INC.
#
# Root only (AppConfig `acls=all`; the page never runs as anyone else).
# Edits only the documented keys in /etc/usertools.conf (0644) and
# /etc/usertools.private.conf (0600, root-only values), with the same
# atomic tmp/chmod/rename writer and validation rules as install.sh:
# booleans, the shell-mode enum list, port range, username/package regex,
# comma lists. Unknown lines and comments in both files are preserved.
# The private file's values are only ever rendered into this root-only
# page, never anywhere else.
#
# CSRF: WHM serves this page under a security-token URL; every form posts
# back to the same relative URL (the token stays in the path) and echoes a
# hidden token field when one is present. No absolute URLs anywhere.
#
# Update check: opt-in (`enable_update_check=1` plus `update_repo`), one
# HTTPS GET to the GitHub releases API with a 5 s timeout, no user or
# server data sent. It only reports; it never downloads or installs.
#
# When required as a module (tests), main() does not run:
#   require "whm/cgi/addon_usertools_settings.cgi";
package UserTools::WHM::Settings;

use strict;
use warnings;

use Fcntl qw(:flock);

# Overridable locations (tests drive these; production uses the defaults).
our $CONF         = '/etc/usertools.conf';
our $PRIVATE_CONF = '/etc/usertools.private.conf';
our $AUDIT_LOG    = '/var/log/usertools.log';
our $VERSION_FILE = '/usr/local/cpanel/3rdparty/usertools/VERSION';
our $UPDATE_TIMEOUT = 5;
our $UPDATER      = '/usr/local/cpanel/3rdparty/usertools/bin/usertools-update';
our $AUTO_STATUS  = '/var/cpanel/usertools/autoupdate.status';
our $CPANEL_CONFIG = '/var/cpanel/cpanel.config';

# Root-check seam: undef in production (uses Whostmgr::ACLS below); tests
# inject `sub { (1, undef) }` or `sub { (0, $error) }`.
our $ACL_CHECK;

# Documented keys: [file, kind]. Kinds: bool, modelist, userlist, pkglist,
# seconds, repo, path, scope. app_packages names live in /var/cpanel/packages/<name>.
our %KEYS = (
    enable_shell            => [ 'conf', 'bool' ],
    allowed_shell_modes     => [ 'conf', 'modelist' ],
    enable_fix_home         => [ 'conf', 'bool' ],
    enable_bulk_perms       => [ 'conf', 'bool' ],
    enable_ownership_report => [ 'conf', 'bool' ],
    enable_app_helper       => [ 'conf', 'bool' ],
    enable_space_cleaner    => [ 'conf', 'bool' ],
    cleaner_log_min_mb      => [ 'conf', 'megabytes' ],
    cleaner_trash_days      => [ 'conf', 'days' ],
    allow_user_app_docroot  => [ 'conf', 'bool' ],
    app_packages            => [ 'conf', 'pkglist' ],
    max_job_seconds         => [ 'conf', 'seconds' ],
    enable_update_check     => [ 'conf', 'bool' ],
    update_repo             => [ 'conf', 'repo' ],
    auto_update             => [ 'conf', 'bool' ],
    auto_update_scope       => [ 'conf', 'scope' ],
    enable_site_doctor      => [ 'conf', 'bool' ],
    enable_exposed_files    => [ 'conf', 'bool' ],
    enable_cron_doctor      => [ 'conf', 'bool' ],
    composer_path           => [ 'conf', 'path' ],
    composer_lift_disable_functions => [ 'conf', 'bool' ],
    normal_shell_users      => [ 'private', 'userlist' ],
);

our $PACKAGES_DIR = '/var/cpanel/packages';

# Composer locations after the admin-set composer_path — same order
# as @Cpanel::API::UserTools::COMPOSER_DEFAULT_PATHS in the UAPI module
# (keep both lists in sync); a package var so tests can localise it.
our @COMPOSER_DEFAULT_PATHS = (
    '/usr/local/bin/composer',           # getcomposer.org global install
    '/opt/cpanel/composer/bin/composer', # fallback
);

# CageFS locations: the mount-points file proves CageFS is active;
# conf.d holds the INI entries. Package vars so tests can point them at
# fixtures; production uses the real paths.
our $CAGEFS_MP     = '/etc/cagefs/cagefs.mp';
our $CAGEFS_CONF_D = '/etc/cagefs/conf.d';

sub _valid_package_name {
    # WHM package names may contain spaces (and reseller prefixes); never
    # ',', '=', a newline or '/'.
    my ($name) = @_;
    return 0 unless defined $name;
    ( my $n = $name ) =~ s/^\s+|\s+$//g;
    return 0 if $n eq '';
    return 0 if $n =~ /[,=\/\n\r]/;
    return 0 unless $n =~ /^[A-Za-z0-9_. \-]+$/;
    return 0 if $n =~ /^\.+$/;
    return 1;
}

sub _valid_username {
    my ($name) = @_;
    return ( defined $name && $name =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/ ) ? 1 : 0;
}

sub _valid_list_name {
    my ($name) = @_;
    return 0 unless defined $name && $name =~ /^[A-Za-z0-9_.-]+$/;
    return 0 if $name =~ /^\.+$/;
    return 1;
}

sub _valid_port {
    my ($port) = @_;
    return ( defined $port && $port =~ /^\d+$/ && $port >= 1 && $port <= 65535 ) ? 1 : 0;
}

sub _split_list {
    my ($text) = @_;
    return () unless defined $text && $text ne '';
    return map { s/^\s+|\s+$//gr } split /,/, $text;
}

sub read_settings {
    my ( $conf, $private ) = @_;
    $conf    = $CONF         unless defined $conf;
    $private = $PRIVATE_CONF unless defined $private;
    my %vals = (
        enable_shell => '1', allowed_shell_modes => 'disabled,jailed',
        enable_fix_home => '1', enable_bulk_perms => '1',
        enable_ownership_report => '1', enable_app_helper => '1',
        enable_space_cleaner => '0', cleaner_log_min_mb => '50',
        cleaner_trash_days => '7', enable_site_doctor => '0',
        enable_exposed_files => '0', enable_cron_doctor => '0',
        allow_user_app_docroot => '0', app_packages => '',
        max_job_seconds => '3600', enable_update_check => '0',
        update_repo => '', auto_update => '0', auto_update_scope => 'patch',
        normal_shell_users => '', ssh_port => '',
        composer_path => '', composer_lift_disable_functions => '0',
    );
    for my $file ( $conf, $private ) {
        if ( open my $fh, '<', $file ) {
            while ( my $line = <$fh> ) {
                my $raw = $line;
                $raw =~ s/^\s+|\s+$//g;
                next if $raw eq '' || $raw =~ /^[#;]/ || $raw =~ /^\[/;
                next unless $raw =~ /=/;
                my ( $k, $v ) = split /=/, $raw, 2;
                $k =~ s/^\s+|\s+$//g;
                $v =~ s/\s*[;#].*$//;
                $v =~ s/^\s+|\s+$//g;
                $vals{$k} = $v if exists $vals{$k};
            }
            close $fh;
        }
    }
    # The ssh_port display value is taint-checked before render.
    if ( !$vals{ssh_port} || !_valid_port( $vals{ssh_port} ) ) {
        $vals{ssh_port} = '';
    }
    return \%vals;
}

sub validate_settings {
    my ( $in_hr, $pkg_dir ) = @_;
    # Returns (\%clean, \@errors). Every documented key is validated;
    # anything else in %$in_hr is ignored (never written). Package names are
    # checked against the existing package files in $pkg_dir.
    $pkg_dir = $PACKAGES_DIR unless defined $pkg_dir;
    my ( %clean, @errors );
    for my $key ( sort keys %KEYS ) {
        my ( $file, $kind ) = @{ $KEYS{$key} };
        my $v = $in_hr->{$key};
        $v = '' unless defined $v;
        $v =~ s/^\s+|\s+$//g;
        if ( $kind eq 'bool' ) {
            # The lift key defaults to 0 when an old form posts without
            # it (never set by default; explicit opt-in only).
            if ( $key eq 'composer_lift_disable_functions' && $v eq '' ) {
                $clean{$key} = '0';
            }
            elsif ( $v eq '1' || $v eq '0' ) {
                $clean{$key} = $v;
            }
            else {
                push @errors, "$key must be 0 or 1";
            }
        }
        elsif ( $kind eq 'modelist' ) {
            my @modes = _split_list($v);
            my %ok = map { $_ => 1 } qw(disabled jailed normal);
            my @bad = grep { !$ok{$_} } @modes;
            if ( !@modes ) {
                push @errors, "$key needs at least one mode";
            }
            elsif (@bad) {
                push @errors, "$key has unknown modes: @bad";
            }
            else {
                $clean{$key} = join( ',', @modes );
            }
        }
        elsif ( $kind eq 'userlist' ) {
            my @names = _split_list($v);
            my @bad = grep { !_valid_username($_) } @names;
            if (@bad) {
                push @errors, "$key has invalid names: @bad";
            }
            else {
                $clean{$key} = join( ',', @names );
            }
        }
        elsif ( $kind eq 'pkglist' ) {
            my @names = _split_list($v);
            my @bad = grep { !_valid_package_name($_) } @names;
            if (@bad) {
                push @errors, "$key has invalid names: @bad";
            }
            else {
                my @missing = grep { !-f "$pkg_dir/$_" } @names;
                if (@missing) {
                    push @errors, "$key has unknown packages: @missing";
                }
                else {
                    $clean{$key} = join( ',', @names );
                }
            }
        }
        elsif ( $kind eq 'seconds' ) {
            if ( $v =~ /^\d+$/ && $v >= 60 && $v <= 86400 ) {
                $clean{$key} = "$v";
            }
            else {
                push @errors, "$key must be 60..86400 seconds";
            }
        }
        elsif ( $kind eq 'megabytes' ) {
            # Log size floor for the Space Cleaner (matches the engine's
            # fenced range; out-of-range falls back to the default there).
            if ( $v =~ /^\d+$/ && $v >= 1 && $v <= 1024 ) {
                $clean{$key} = "$v";
            }
            else {
                push @errors, "$key must be 1..1024 MB";
            }
        }
        elsif ( $kind eq 'days' ) {
            # Trash age for the Space Cleaner (matches the engine's range).
            if ( $v =~ /^\d+$/ && $v >= 1 && $v <= 90 ) {
                $clean{$key} = "$v";
            }
            else {
                push @errors, "$key must be 1..90 days";
            }
        }
        elsif ( $kind eq 'repo' ) {
            if ( $v eq '' || $v =~ m{^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$} ) {
                $clean{$key} = $v;
            }
            else {
                push @errors, "$key must be empty or owner/repo";
            }
        }
        elsif ( $kind eq 'scope' ) {
            if ( $v eq 'patch' || $v eq 'minor' ) {
                $clean{$key} = $v;
            }
            else {
                push @errors, "$key must be patch or minor";
            }
        }
        elsif ( $kind eq 'path' ) {
            # Absolute path only (empty = auto-discover); the character
            # class keeps whitespace, quotes and comment bytes out of the
            # conf line — the same shape the user-side reader accepts.
            if ( $v eq '' || $v =~ m{^/[A-Za-z0-9][A-Za-z0-9._+/-]*$} ) {
                $clean{$key} = $v;
            }
            else {
                push @errors, "$key must be empty or an absolute path";
            }
        }
    }
    return ( \%clean, \@errors );
}

sub _write_one_file {
    my ( $path, $want_hr, $mode ) = @_;
    # Atomic replace-or-append per key (same semantics as install.sh's
    # set_key): other lines and comments are preserved byte-for-byte.
    my @lines;
    if ( open my $fh, '<', $path ) {
        @lines = <$fh>;
        close $fh;
    }
    my %done;
    for my $line (@lines) {
        my $probe = $line;
        for my $k ( keys %{$want_hr} ) {
            if ( !$done{$k} && index( $probe, "$k=" ) == 0 ) {
                $line      = "$k=$want_hr->{$k}\n";
                $done{$k}  = 1;
                last;
            }
        }
    }
    for my $k ( sort keys %{$want_hr} ) {
        if ( !$done{$k} ) {
            push @lines, "$k=$want_hr->{$k}\n";
        }
    }
    my $tmp = "$path.usertools-new.$$";
    if ( open my $fh, '>', $tmp ) {
        print $fh @lines;
        close $fh;
        chmod $mode, $tmp;
        if ( rename( $tmp, $path ) ) {
            return 1;
        }
        unlink $tmp;
    }
    return 0;
}

sub write_settings {
    my ( $conf, $private, $clean_hr ) = @_;
    $conf    = $CONF         unless defined $conf;
    $private = $PRIVATE_CONF unless defined $private;
    my ( %to_conf, %to_private );
    for my $key ( keys %{$clean_hr} ) {
        next unless exists $KEYS{$key};
        if ( $KEYS{$key}[0] eq 'private' ) {
            $to_private{$key} = $clean_hr->{$key};
        }
        else {
            $to_conf{$key} = $clean_hr->{$key};
        }
    }
    if ( !_write_one_file( $conf, \%to_conf, 0644 ) ) {
        return 0;
    }
    if ( !_write_one_file( $private, \%to_private, 0600 ) ) {
        return 0;
    }
    return 1;
}

sub audit_tail {
    my ( $log, $n ) = @_;
    $log = $AUDIT_LOG unless defined $log;
    $n = 200 unless defined $n;
    if ( open my $fh, '<', $log ) {
        my @lines = <$fh>;
        close $fh;
        chomp @lines;
        if ( @lines > $n ) {
            @lines = @lines[ $#lines - $n + 1 .. $#lines ];
        }
        return \@lines;
    }
    return [];
}

sub installed_version {
    my ($file) = @_;
    $file = $VERSION_FILE unless defined $file;
    if ( open my $fh, '<', $file ) {
        my $v = <$fh>;
        close $fh;
        if ( defined $v ) {
            $v =~ s/^\s+|\s+$//g;
            return $v if $v ne '';
        }
    }
    return 'unknown';
}

sub _compare_versions {
    my ( $a, $b ) = @_;
    # Tolerant dotted-numeric compare; falls back to string equality.
    for ( $a, $b ) {
        s/^v//i;
    }
    my @a = split /[^0-9]+/, $a;
    my @b = split /[^0-9]+/, $b;
    my $n = @a > @b ? scalar @a : scalar @b;
    for my $i ( 0 .. $n - 1 ) {
        my $x = $i < @a ? ( $a[$i] || 0 ) : 0;
        my $y = $i < @b ? ( $b[$i] || 0 ) : 0;
        if ( $x != $y ) {
            return $x <=> $y;
        }
    }
    return $a eq $b ? 0 : ( $a lt $b ? -1 : 1 );
}

sub update_check {
    my ( $current, $repo, $fetch_sub ) = @_;
    # Opt-in update report (never downloads or installs): one HTTPS GET to
    # the GitHub releases API, 5 s timeout, no user or server data sent.
    # $fetch_sub is the test seam; production uses HTTP::Tiny below.
    if ( !defined $repo || $repo eq '' ) {
        return { error => 'Set update_repo (owner/repo) first.' };
    }
    my $url = "https://api.github.com/repos/$repo/releases/latest";
    my $data = eval {
        defined $fetch_sub ? $fetch_sub->($url) : _fetch_release($url);
    };
    if ( $@ || ref $data ne 'HASH' ) {
        return { error => 'Update check failed (network or unreadable reply).' };
    }
    my $latest = $data->{tag_name} // '';
    $latest =~ s/^\s+|\s+$//g;
    if ( $latest eq '' ) {
        return { error => 'Update check failed (no release found).' };
    }
    my $cmp = eval { _compare_versions( $current, $latest ) };
    if ( $@ || !defined $cmp ) {
        return { error => 'Update check failed (uncomparable versions).' };
    }
    return {
        current => $current, latest => $latest,
        url => $data->{html_url} // "https://github.com/$repo/releases",
        update_available => $cmp < 0 ? 1 : 0,
    };
}

sub _fetch_release {
    my ($url) = @_;
    require HTTP::Tiny;
    my $ua = HTTP::Tiny->new( timeout => $UPDATE_TIMEOUT, verify_SSL => 1 );
    my $resp = $ua->get( $url, { headers => { 'Accept' => 'application/vnd.github+json' } } );
    if ( !$resp->{success} ) {
        die "fetch failed: $resp->{status}";
    }
    require JSON::PP;
    my $data = eval { JSON::PP->new()->decode( $resp->{content} ) };
    if ( $@ || ref $data ne 'HASH' ) {
        die 'unreadable reply';
    }
    return $data;
}

sub _test_mode {
    # Test seams (USERTOOLS_* env) are honoured only when
    # USERTOOLS_TEST_MODE=1 is set AND the effective uid is not 0. Tests
    # run unprivileged with the flag; production (root, or flag absent)
    # always uses the compiled-in defaults.
    return ( ( $ENV{USERTOOLS_TEST_MODE} // '' ) eq '1' && $> != 0 ) ? 1 : 0;
}

sub run_updater {
    # Runs the shipped updater with the ONE fixed action (--update): no tag,
    # URL, version or any other caller data crosses the boundary (tested).
    # The child gets a clean environment (PATH only) so the CGI's
    # inherited environment — including any USERTOOLS_* — can never redirect
    # the updater as root, with the fixed root PATH (sbin included).
    # Returns (message, undef) or (undef, error).
    local %ENV = ( PATH => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' );
    my @cmd = ( $UPDATER, '--update' );
    my $fh;
    if ( !open $fh, '-|', @cmd ) {
        return ( undef, "cannot run updater: $!" );
    }
    local $/;
    my $out = <$fh>;
    close $fh;
    $out = '' unless defined $out;
    $out =~ s/^\s+|\s+$//g;
    if ( $? != 0 ) {
        my ($last) = $out =~ /^(.*)$/m;
        return ( undef, defined $last && $last ne '' ? $last : 'update failed' );
    }
    return ( $out ne '' ? $out : 'Update finished.', undef );
}

sub read_auto_status {
    # Last automatic-update outcome stamp, or undef when none. Broken or
    # partial files read as absent (banner simply stays hidden).
    my ($path) = @_;
    $path = $AUTO_STATUS unless defined $path;
    my %st;
    if ( open my $fh, '<', $path ) {
        while ( my $line = <$fh> ) {
            $line =~ s/^\s+|\s+$//g;
            next unless $line =~ /=/;
            my ( $k, $v ) = split /=/, $line, 2;
            $k =~ s/^\s+|\s+$//g;
            $v = '' unless defined $v;
            $v =~ s/^\s+|\s+$//g;
            $st{$k} = $v if $k =~ /^(ok|reason|at)$/;
        }
        close $fh;
    }
    return undef unless exists $st{ok};
    return \%st;
}

sub jail_default_on {
    # Reads WHM Tweak Settings' "Use cPanel jailshell by default"
    # (cpanel.config jaildefaultshell) for the readiness row. Returns 1
    # (on), 0 (explicitly off), undef (unreadable — row stays hidden).
    # Same semantics as the Admin gate: absent key means on.
    my ($path) = @_;
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
    return undef;
}

sub feature_list_help {
    my ( $list, $feature, $dir ) = @_;
    # No silent changes: validate the list, confirm it exists, and return
    # the exact WHM click-path with the feature to tick. (Using a Feature
    # Manager write API is a possible follow-up.)
    $dir = '/var/cpanel/features' unless defined $dir;
    if ( !_valid_list_name($list) ) {
        return { error => 'Invalid feature list name.' };
    }
    my $path = "$dir/$list";
    if ( !-f $path ) {
        return { error => "Feature list '$list' does not exist on this server." };
    }
    return {
        steps => "WHM >> Home >> Packages >> Feature Manager >> Manage feature list '$list' "
          . ">> tick '$feature' >> Save.",
        feature => $feature,
        list    => $list,
    };
}

sub _composer_bin_check {
    my ($bin) = @_;
    # The same gate as the user-side _find_composer: a regular
    # executable that is root-owned and not writable by group or others.
    # Returns 'ok' | 'missing' | 'unsafe' (+ reason).
    my @st = lstat $bin;
    return ( 'missing', 'not found' )          unless @st;
    return ( 'missing', 'not a regular file' ) unless -f _;
    return ( 'missing', 'not executable' )     unless -x _;
    if ( $st[4] != 0 || ( $st[2] & 0022 ) != 0 ) {
        return ( 'unsafe', 'not root-owned or writable by group/others' );
    }
    return ( 'ok', undef );
}

sub composer_candidates {
    my ($conf) = @_;
    # [path, source] pairs in the same order as the user-side
    # _find_composer (keep both lists in sync): an admin-set
    # composer_path from the public conf, then the getcomposer.org
    # global-install location, then the /opt/cpanel fallback.
    $conf = $CONF unless defined $conf;
    my @cands;
    my $set = read_settings($conf)->{composer_path} // '';
    push @cands, [ $set, 'composer_path (admin setting)' ] if $set ne '';
    my @labels = ('getcomposer.org global install', 'fallback location');
    for my $i ( 0 .. $#COMPOSER_DEFAULT_PATHS ) {
        push @cands, [ $COMPOSER_DEFAULT_PATHS[$i], $labels[$i] // 'default location' ];
    }
    return @cands;
}

sub _cagefs_active {
    # CageFS present and enabled (root side, for the admin hint).
    return -f $CAGEFS_MP ? 1 : 0;
}

sub _path_visible_in_cage {
    # True when CageFS is off, or when $path is literally listed in any
    # conf.d *.cfg entry (the INI `paths=` list) or in cagefs.mp.
    # Fail OPEN like the user side: an unprovable absence (unreadable
    # configs) must never veto a path that passed the ownership check.
    my ($path) = @_;
    return 1 unless _cagefs_active();
    my ( $listed, $read_any ) = ( 0, 0 );
    if ( opendir my $dh, $CAGEFS_CONF_D ) {
        $listed = 1;
        my @files = grep { /\.cfg$/ } readdir $dh;
        closedir $dh;
        for my $f (@files) {
            if ( open my $fh, '<', "$CAGEFS_CONF_D/$f" ) {
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
    if ( open my $fh, '<', $CAGEFS_MP ) {
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

sub find_composer {
    my ( $conf, $bin_check ) = @_;
    # What the page shows the admin: which composer would actually run
    # (found + where it came from), a configured-but-unsafe composer_path
    # (path + reason — the search stops there, exactly like the user-side
    # code), a path that exists on the host but is not mounted into the
    # cage (found, but not visible to caged users, with the conf.d
    # remedy), or nothing found (the template then prints how to install).
    # $bin_check is the test seam for the ownership check.
    $bin_check = \&_composer_bin_check unless defined $bin_check;
    for my $c ( composer_candidates($conf) ) {
        my ( $state, $why ) = $bin_check->( $c->[0] );
        if ( $state eq 'ok' ) {
            if ( !_path_visible_in_cage( $c->[0] ) ) {
                return {
                    found => 0, path => $c->[0], source => $c->[1],
                    reason =>
                      'found, but not visible to caged users (add a CageFS conf.d INI entry for this path, then run cagefsctl --force-update)',
                    cagefs => 1,
                };
            }
            return { found => 1, path => $c->[0], source => $c->[1] };
        }
        if ( $state eq 'unsafe' ) {
            return { found => 0, path => $c->[0], source => $c->[1], reason => $why };
        }
    }
    return { found => 0, reason => 'no composer binary found' };
}

# Cosign locations (fixed paths only, never PATH as root). Same
# ownership rule as Composer: root-owned, no group/other write.
our @COSIGN_PATHS = ( '/usr/local/bin/cosign', '/usr/bin/cosign' );

sub _cosign_bin_check {
    my ($bin) = @_;
    my @st = lstat $bin;
    return ( 'missing', 'not found' )          unless @st;
    return ( 'missing', 'not a regular file' ) unless -f _;
    return ( 'missing', 'not executable' )     unless -x _;
    if ( $st[4] != 0 || ( $st[2] & 0022 ) != 0 ) {
        return ( 'unsafe', 'not root-owned or writable by group/others' );
    }
    return ( 'ok', undef );
}

sub find_cosign {
    # What the Updates section shows: which cosign the updater would use,
    # or not found (the template then prints the install command and
    # disables the Update button). $bin_check is the test seam.
    my ($bin_check) = @_;
    $bin_check = \&_cosign_bin_check unless defined $bin_check;
    for my $c (@COSIGN_PATHS) {
        my ( $state, $why ) = $bin_check->($c);
        if ( $state eq 'ok' ) {
            return { found => 1, path => $c };
        }
        if ( $state eq 'unsafe' ) {
            return { found => 0, path => $c, reason => $why };
        }
    }
    return { found => 0, reason => 'cosign not found' };
}

sub _require_root {
    if ( defined $ACL_CHECK ) {
        return $ACL_CHECK->();
    }
    my $has = eval {
        require Whostmgr::ACLS;
        Whostmgr::ACLS::init_acls();
        Whostmgr::ACLS::hasroot() ? 1 : 0;
    };
    if ( $@ || !$has ) {
        return ( 0, 'Access denied: root only.' );
    }
    return ( 1, undef );
}

sub _uri_decode {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ tr/+/ /;
    $s =~ s/%([0-9A-Fa-f]{2})/chr( hex($1) )/ge;
    return $s;
}

sub _parse_urlencoded {
    my ( $s, $hr ) = @_;
    for my $pair ( split /[&;]/, $s // '' ) {
        next unless length $pair;
        my ( $k, $v ) = split /=/, $pair, 2;
        $hr->{ _uri_decode($k) } = _uri_decode($v);
    }
    return;
}

sub _read_request {
    # Minimal GET/POST urlencoded parsing with core only (CGI.pm is not core
    # and cPanel must not be assumed to ship it). Returns ($method, \%params).
    # Bodies over 1 MiB are ignored rather than read.
    my $method = uc( $ENV{REQUEST_METHOD} // 'GET' );
    my %p;
    my $qs = $ENV{QUERY_STRING} // '';
    _parse_urlencoded( $qs, \%p ) if $qs ne '';
    if ( $method eq 'POST' ) {
        my $len = $ENV{CONTENT_LENGTH} // 0;
        if ( $len =~ /^\d+$/ && $len > 0 && $len <= 1048576 ) {
            my $body = '';
            my $n = read( STDIN, $body, $len );
            $body = '' unless defined $n;
            _parse_urlencoded( $body, \%p );
        }
    }
    return ( $method, \%p );
}

sub _log_error {
    my ($msg) = @_;
    # Template/hook detail goes to the root-only audit log, never the page.
    my @t = gmtime();
    my $ts = sprintf( "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0] );
    if ( open my $fh, '>>', $AUDIT_LOG ) {
        flock( $fh, LOCK_EX );
        print $fh "$ts template error: $msg\n";
        close $fh;
        chmod 0600, $AUDIT_LOG;
    }
    return;
}

sub _render_whm {
    my ( $tpl_rel, $vars_hr ) = @_;
    # WHM chrome through Cpanel::Template (Guide to WHM Plugins - Plugin
    # Files: process_template('whostmgr', {template_file, print => 1})).
    # Extra hash keys travel as template variables.
    # Returns undef when the page printed, else the error text. Never dies.
    my ( $ret, $err );
    {
        local $@;
        $ret = eval {
            require Cpanel::Template;
            Cpanel::Template::process_template(
                'whostmgr',
                { template_file => $tpl_rel, print => 1, %{$vars_hr} },
            );
        };
        $err = $@;
    }
    if ( $err || !$ret ) {
        my $msg = $err || 'template failed';
        chomp $msg;
        return $msg;
    }
    return undef;
}

sub main {
    # Root first, before any input or file is read: AppConfig controls
    # the menu, but a reseller opening this URL directly must still get a
    # 403. Uses the documented WHM plugin pattern (Guide to WHM Plugins):
    # Whostmgr::ACLS::init_acls() then Whostmgr::ACLS::hasroot().
    my ( $root_ok, $root_err ) = _require_root();
    if ( !$root_ok ) {
        print "Status: 403 Forbidden\nContent-type: text/plain; charset=utf-8\n\n$root_err\n";
        return;
    }
    my ( $method, $in_hr ) = _read_request();
    my %in = %{$in_hr};
    my $token = $in{cpsess} // $in{token} // '';
    my ( $message, @errors, $update );
    my $action = $in{action} // '';
    if ( $action eq 'save' && $method eq 'POST' ) {
        my ( $clean, $errs ) = validate_settings( \%in );
        @errors = @{$errs};
        # Auto-update never enables itself without cosign (the updater
        # refuses without a signature anyway; the page refuses first).
        if ( !@errors && ( $clean->{auto_update} // '' ) eq '1' && !find_cosign()->{found} ) {
            push @errors, 'Automatic updates need cosign to verify releases (install cosign first).';
        }
        if ( !@errors ) {
            if ( write_settings( undef, undef, $clean ) ) {
                $message = 'Settings saved.';
            }
            else {
                push @errors, 'Could not write the settings files.';
            }
        }
    }
    elsif ( $action eq 'save' ) {
        push @errors, 'Save requires POST.';
    }
    elsif ( $action eq 'check_updates' ) {
        my $cur = read_settings();
        if ( ( $cur->{enable_update_check} // '' ) ne '1' ) {
            push @errors, 'Enable the update check first (opt-in).';
        }
        else {
            $update = update_check( installed_version(), $cur->{update_repo} );
            if ( $update->{error} ) {
                push @errors, $update->{error};
                $update = undef;
            }
        }
    }
    elsif ( $action eq 'update_now' && $method eq 'POST' ) {
        my ( $msg, $err ) = run_updater();
        if ( defined $err ) {
            push @errors, $err;
        }
        else {
            $message = $msg;
        }
        my $cur = read_settings();
        if ( ( $cur->{enable_update_check} // '' ) eq '1' ) {
            my $fresh = update_check( installed_version(), $cur->{update_repo} );
            $update = $fresh unless $fresh->{error};
        }
    }
    elsif ( $action eq 'update_now' ) {
        push @errors, 'Update requires POST.';
    }
    elsif ( $action eq 'feature_help' ) {
        my $help = feature_list_help( $in{list} // '', $in{feature} // '' );
        if ( $help->{error} ) {
            push @errors, $help->{error};
        }
        else {
            $message = $help->{steps};
        }
    }
    my $settings = read_settings();
    my $audit    = audit_tail();
    my $version  = installed_version();
    my $composer = find_composer();
    my $auto_status = read_auto_status();
    my $jail_default = jail_default_on();
    # Tri-state from the reader (1/0/undef) becomes an explicit flag:
    # warn only on explicitly-off; unreadable stays silent.
    my $jail_default_off = ( defined $jail_default && $jail_default == 0 ) ? 1 : 0;
    my $cosign = find_cosign();
    # Absolute installed path (verified: process_template does not
    # resolve docroot-relative paths). Header first, per the doc example.
    # The template override is a test seam only (test mode + non-root);
    # production always uses the installed path.
    my $tpl = ( _test_mode() ? $ENV{USERTOOLS_WHM_TEMPLATE} : undef )
      // '/usr/local/cpanel/whostmgr/docroot/addon/usertools/settings.tt';
    print "Content-type: text/html; charset=utf-8\r\n\r\n";
    my $tpl_err = _render_whm(
        $tpl,
        {
            settings => $settings, errors => \@errors, message => $message,
            audit => $audit, version => $version, update => $update,
            token => $token, composer => $composer,
            auto_status => $auto_status, cosign => $cosign,
            jail_default_off => $jail_default_off,
        }
    );
    if ( defined $tpl_err ) {
        print '<p>Template error</p>';
        _log_error($tpl_err);
    }
    return;
}

main() unless caller;

1;
