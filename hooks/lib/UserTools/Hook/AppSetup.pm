# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
package UserTools::Hook::AppSetup;

# Standardized hook: Whostmgr::Accounts::Create, post stage.
#
# "App packages" automation: for a new account whose package is listed in
# app_packages= (and enable_app_helper=1), prepare public_html/public as
# the USER (privilege drop — root never touches user paths), switch the
# primary docroot to public_html/public as root (WHM API 1 + verification +
# audit, shared with AppDocroot via Base), then write the .htaccess pair as
# the user (public file, then the root lock; _ht_root_plan is consulted even
# though a new account has no nested domains).
#
# A hook failure NEVER fails account creation: _run() is fully eval-guarded,
# the reason is logged, and hook() always returns 0.
#
# Verified on a live server: the manage_hooks registration shape,
# Cpanel::AccessIds::do_as_user in hook context, and @INC visibility of the
# installed modules from the hook process.
use strict;
use warnings;

use Fcntl qw(:flock O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);

# Overridable locations (tests drive these; production uses the defaults).
our $CONF         = '/etc/usertools.conf';
our $WHMAPI1      = '/usr/local/cpanel/bin/whmapi1';
our $UAPI         = '/usr/local/cpanel/bin/uapi';
our $AUDIT_LOG    = '/var/log/usertools.log';
our $USERTOOLS_PM = '/usr/local/cpanel/Cpanel/API/UserTools.pm';
our $BASE_PM      = '/usr/local/cpanel/Cpanel/Admin/Modules/UserTools/Base.pm';

# Privilege-drop seam: undef in production (uses the documented
# Cpanel::AccessIds::do_as_user); tests inject a coderef.
our $DO_AS_USER;

use constant DOCROOT_APP => 'public_html/public';

sub describe {
    # Metadata read by `manage_hooks add module` (Guide to Standardized
    # Hooks - The describe() Method: an arrayref of hashes with at least
    # category, event, stage, exectype and hook). Mirrored by install.sh.
    return [
        {
            category => 'Whostmgr',
            event    => 'Accounts::Create',
            stage    => 'post',
            exectype => 'module',
            hook     => 'UserTools::Hook::AppSetup::hook',
        },
    ];
}

sub _valid_username {
    my ($user) = @_;
    return ( defined $user && $user =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/ ) ? 1 : 0;
}

sub _log {
    my ($msg) = @_;
    my @t = gmtime();
    my $ts = sprintf( "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0] );
    if ( open my $fh, '>>', $AUDIT_LOG ) {
        flock( $fh, LOCK_EX );
        print $fh "$ts $msg\n";
        close $fh;
        chmod 0600, $AUDIT_LOG;
    }
    return;
}

sub _as_user {
    my ( $user, $code ) = @_;
    if ( defined $DO_AS_USER ) {
        return $DO_AS_USER->( $user, $code );
    }
    require Cpanel::AccessIds;
    return Cpanel::AccessIds::do_as_user( $user, $code );
}

sub _refuse_symlink_dir {
    my ($dir) = @_;
    # lstat (never follows): the path must exist, be a directory, and not a
    # symlink. Dies with a plain message the hook logs.
    my @st = lstat $dir;
    if ( !@st ) {
        die "missing directory: $dir";
    }
    if ( -l _ ) {
        die "refusing symlink: $dir";
    }
    if ( !-d _ ) {
        die "not a directory: $dir";
    }
    return 1;
}

sub _write_new_file {
    my ( $path, $content, $mode ) = @_;
    # Create-only write (O_CREAT|O_EXCL|O_NOFOLLOW): never follows or
    # replaces a symlink, never clobbers. Exact mode afterwards.
    my @st = lstat $path;
    if (@st) {
        die "already exists: $path";
    }
    my $fh;
    if ( !sysopen( $fh, $path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, $mode ) ) {
        die "cannot create $path: $!";
    }
    print $fh $content;
    if ( !close $fh ) {
        die "cannot write $path: $!";
    }
    chmod $mode, $path;
    return 1;
}

sub _placeholder_index {
    return <<'PHP';
<?php
// UserTools placeholder: this account is prepared for a Laravel app.
// Deploy the application into public_html/; this file is replaced then.
http_response_code(200);
echo "Account ready.\n";
PHP
}

sub _default_ht_options {
    return (
        nonwww => 1, slash => 1, expires => 1,
        https => 0, indexphp => 0, auth => 0, sitemap => 0,
    );
}

sub _hook_field {
    my ( $data, @names ) = @_;
    # Tolerant field lookup for Accounts::Create data (the event returns the
    # WHM API 1 createacct returns; script-side examples read
    # data->{domain}/data->{contactemail}/data->{plan}). Accepts both the
    # flat hash and the {data:{...}} envelope, first defined non-ref wins.
    for my $src ( $data, ( ref $data eq 'HASH' ? $data->{data} : () ) ) {
        next unless ref $src eq 'HASH';
        for my $k (@names) {
            if ( defined $src->{$k} && !ref $src->{$k} && $src->{$k} ne '' ) {
                return $src->{$k};
            }
        }
    }
    return undef;
}

sub hook {
    my ( $context, $data ) = @_;
    # Called by cPanel as hook($context, $data): $context is the
    # "Category::Event" string, $data the event hash (Guide to Standardized
    # Hooks - Hook Action Code). Returns bare 1/0: the doc's ($result,
    # $message) list form would read as success in scalar context on
    # failure, while bare scalars are unambiguous in both. Post-stage cannot
    # block account creation anyway; failures are logged.
    my $ok = eval { _run($data); 1 };
    if ( !$ok ) {
        my $err = $@ || 'unknown hook error';
        chomp $err;
        _log("app-setup failed: $err (account creation continues)");
        return 0;
    }
    return 1;
}

sub _run {
    my ($data) = @_;
    my $user = _hook_field( $data, qw(user username newuser) );
    my $pkg  = _hook_field( $data, qw(package plan pkg) );
    if ( !_valid_username($user) ) {
        die "no usable username in hook data";
    }
    my @pw = getpwnam($user);
    if ( !@pw ) {
        die "unknown account $user";
    }
    my $home = $pw[7];
    if ( !defined $home || $home eq '' || $home eq '/' ) {
        die "bad home for $user";
    }

    require $BASE_PM;
    my $policy = Cpanel::Admin::Modules::UserTools::Base::_read_policy($CONF);
    if ( ( $policy->{enable_app_helper} // '' ) ne '1' ) {
        return 0;
    }
    my %pkgs = map { $_ => 1 }
      grep { $_ ne '' } map { s/^\s+|\s+$//gr } split /,/, ( $policy->{app_packages} // '' );
    if ( !exists $pkgs{$pkg} ) {
        return 0;
    }

    require $USERTOOLS_PM;
    my $public = "$home/public_html/public";

    # Step 1 (as the user): layout + placeholder + public .htaccess. Each
    # file operation is labelled so the audit log names the exact file that
    # blocked setup, e.g. a skeleton file that already exists.
    my $guard = sub {
        my ( $what, $code ) = @_;
        my $ok = eval { $code->(); 1 };
        if ( !$ok ) {
            my $err = $@ || 'unknown error';
            chomp $err;
            die "$what blocked setup: $err";
        }
        return 1;
    };
    _as_user(
        $user,
        sub {
            $guard->( "check $home/public_html", sub { _refuse_symlink_dir("$home/public_html") } );
            if ( -l $public ) {
                die "refusing symlink: $public";
            }
            if ( !-d $public ) {
                $guard->(
                    "mkdir $public",
                    sub {
                        require File::Path;
                        File::Path::make_path( $public, { mode => 0755 } );
                        chmod 0755, $public;
                        return 1;
                    }
                );
            }
            $guard->(
                "write $public/index.php",
                sub { _write_new_file( "$public/index.php", _placeholder_index(), 0644 ) } );
            my $pub_new = Cpanel::API::UserTools::_ht_merge(
                undef, Cpanel::API::UserTools::_ht_public_block( _default_ht_options() ) );
            $guard->(
                "write $public/.htaccess",
                sub { _write_new_file( "$public/.htaccess", $pub_new, 0644 ) } );
            return 1;
        }
    );

    # Step 2 (as root): the docroot switch, verified and audited. Only WHM
    # calls here — no file I/O on user paths.
    my ( $ok, $err ) = Cpanel::Admin::Modules::UserTools::Base::_whm_set_primary_docroot(
        $WHMAPI1, $user, DOCROOT_APP );
    if ( !$ok ) {
        die "docroot switch failed: $err";
    }
    my $live = Cpanel::Admin::Modules::UserTools::Base::_read_primary_docroot( $UAPI, $user );
    if ( !defined $live || $live ne "$home/" . DOCROOT_APP ) {
        die 'docroot switch did not take effect';
    }
    Cpanel::Admin::Modules::UserTools::Base::_audit(
        $AUDIT_LOG, $user, "app-setup:$pkg", 'primary-docroot:' . DOCROOT_APP );

    # Step 3 (as the user): the root lock when the layout allows it.
    my $plan = Cpanel::API::UserTools::_ht_root_plan( $user, "$home/public_html" );
    if ( $plan->{write_root} ) {
        my ( $root_new, $root_err ) = Cpanel::API::UserTools::_ht_root_block(
            $user, $home, "$home/public_html" );
        if ( !defined $root_new ) {
            die "root lock refused: $root_err";
        }
        my $root_merged = Cpanel::API::UserTools::_ht_merge( undef, $root_new );
        _as_user(
            $user,
            sub {
                _write_new_file( "$home/public_html/.htaccess", $root_merged, 0644 );
                return 1;
            }
        );
    }
    else {
        my $why = $plan->{skipped} ? 'nested domains' : 'deferred';
        _log("app-setup $user: root lock skipped ($why)");
    }
    _log("app-setup $user on package $pkg: primary docroot " . DOCROOT_APP);
    return 0;
}

1;
