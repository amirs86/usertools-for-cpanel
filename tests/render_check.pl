#!/usr/bin/perl
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Static render of the Jupiter adapters with stock Template Toolkit
# (no cPanel server). It emulates BOTH the installed layout (install.sh
# copies frontend/shared/* next to each adapter, as user_tools/shared/) and
# cPanel's template resolution: every relative INCLUDE/PROCESS resolves
# against the page's own directory ONLY (user_tools/), never against a
# parent directory — so INCLUDE_PATH here is exactly that page dir, plus
# the test-only _assets/master.html.tt stub (the real one ships with
# Jupiter). Proves each adapter compiles, the shared bodies and the footer
# partial resolve as shared/footer.tt, and locale.maketext calls render.
# Run:  perl tests/render_check.pl   (also used by .github/workflows/ci.yml)
use strict;
use warnings;
use FindBin;
use File::Path qw(make_path);
use File::Copy qw(copy);
use Template ();

package FakeLocale;

sub maketext {
    my ( $self, $msg, @args ) = @_;
    my $out = $msg;
    my $i   = 1;
    for my $a (@args) {
        my $n = $i++;
        $out =~ s/\[_$n\]/$a/g;
    }
    return $out;
}

package main;

my $root     = "$FindBin::Bin/..";
my $page_dir = "$root/frontend/jupiter/user_tools";
my $shared   = "$root/frontend/shared";
my $stub_dir = "$FindBin::Bin/tt_stubs";
my $stage    = "$root/build/stage/user_tools";

make_path("$stage/shared");
for my $f (qw(fix_home_permissions.html.tt bulk_permissions.html.tt ownership_report.html.tt manage_shell.html.tt app_helper.html.tt space_cleaner.html.tt)) {
    copy( "$page_dir/$f", "$stage/$f" ) or die "copy $f: $!\n";
}
for my $f (qw(fix_home_body.tt bulk_permissions_body.tt ownership_report_body.tt manage_shell_body.tt app_helper_body.tt space_cleaner_body.tt footer.tt)) {
    copy( "$shared/$f", "$stage/shared/$f" ) or die "copy $f: $!\n";
}

my $tt = Template->new(
    {
        INCLUDE_PATH => [ $stage, $stub_dir ],
        ENCODING     => 'utf8',
    }
);
my $vars = { locale => bless( {}, 'FakeLocale' ), CPANEL => {} };

my %pages = (
    'fix_home_permissions.html.tt' => [
        '<title>Fix Home Permissions</title>', 'id="ut-cards"',
        'id="ut-fix"', 'Learn more', 'as86.pro', 'UT_STR',
    ],
    'bulk_permissions.html.tt' => [
        '<title>Bulk Permissions</title>', 'id="ut-docroot"',
        'ut-progress', 'UT_STR', 'as86.pro', 'Learn more',
        'ut-apply-preview', 'Would change', 'Apply these', 'clearPending',
    ],
    'ownership_report.html.tt' => [
        '<title>Ownership Report</title>', 'id="ut-docroot"',
        'ut-progress', 'UT_STR', 'as86.pro', 'changes nothing',
        'ut-csv', 'ut-copy',
    ],
    'manage_shell.html.tt' => [
        '<title>Manage Shell</title>', 'ut-enable', 'ut-kindrow',
        'UT_STR', 'as86.pro', 'ut-sshcmd', 'ut-dialog', 'jailed shells on',
    ],
    'app_helper.html.tt' => [
        '<title>App Helper</title>', 'ut-addpath', 'ut-apps',
        'UT_STR', 'as86.pro', 'ut-dialog', 'Laravel applications',
    ],
    'space_cleaner.html.tt' => [
        '<title>Space Cleaner</title>', 'ut-cat-error_logs',
        'ut-preview', 'ut-clean', 'UT_STR', 'as86.pro', 'Learn more',
        'ut-trash-list', 'Empty all trash', 'clearPending',
    ],
);

my $fail = 0;
for my $page ( sort keys %pages ) {
    my $out = "$root/build/$page";
    $out =~ s/\.tt$/.html/;
    if ( !$tt->process( $page, $vars, $out ) ) {
        print "render failed ($page): " . $tt->error() . "\n";
        $fail = 1;
        next;
    }
    open my $fh, '<:encoding(utf8)', $out or die "cannot read $out: $!\n";
    my $html = do { local $/; <$fh> };
    close $fh;
    my @missing = grep { index( $html, $_ ) < 0 } @{ $pages{$page} };
    if (@missing) {
        print "render missing ($page): " . join( ', ', @missing ) . "\n";
        $fail = 1;
        next;
    }
    if ( $html !~ /user_tools\/assets\/usertools\.(css|js)/ ) {
        print "render missing ($page): asset links\n";
        $fail = 1;
        next;
    }
    print "render OK: $page\n";
}
# Every <summary> needs a visible marker (Jupiter strips the native
# triangle). The stylesheet must carry the explicit marker rules.
{
    my $css_file = "$root/frontend/jupiter/user_tools/assets/usertools.css";
    open my $cfh, '<:encoding(utf8)', $css_file or die "cannot read $css_file: $!\n";
    my $css = do { local $/; <$cfh> };
    close $cfh;
    for my $rule ( 'summary::before', 'details[open]', 'cursor: pointer', 'summary:hover' ) {
        if ( index( $css, $rule ) < 0 ) {
            print "render missing (css): $rule\n";
            $fail = 1;
        }
    }
    print "render OK: summary markers\n" unless $fail;
}
exit( $fail ? 1 : 0 );
