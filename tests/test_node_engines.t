# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
#
# Node engines range parsing, version reading and binary selection.
use strict;
use warnings;
use Test::More;
use FindBin;
use File::Basename qw(dirname);
use File::Path qw(make_path);
use File::Temp qw(tempdir);

use lib "$FindBin::Bin/lib";
require "$FindBin::Bin/../Cpanel/API/UserTools.pm";

sub write_node_script {
    my ( $path, $body ) = @_;
    make_path( dirname($path) );
    open my $fh, '>', $path or die $!;
    print $fh "#!/bin/sh\n$body\n";
    close $fh;
    chmod 0755, $path;
    return $path;
}

sub write_package {
    my ( $approot, $json ) = @_;
    make_path($approot);
    open my $fh, '>', "$approot/package.json" or die $!;
    print $fh $json;
    close $fh;
    return $approot;
}

sub add_node {
    my ( $home, $family, $major, $body ) = @_;
    my $dir =
        $family eq 'ea'
      ? "$home/cpanel/ea-nodejs$major/bin"
      : "$home/alt/alt-nodejs$major/root/usr/bin";
    return write_node_script( "$dir/node", $body );
}

subtest 'range table and boundaries' => sub {
    my @cases = (
        [ '18',            '17.9.9', 'no' ],
        [ '18',            '18.0.0', 'ok' ],
        [ '18',            '18.9.9', 'ok' ],
        [ '18',            '19.0.0', 'no' ],
        [ '18.x',          '18.0.0', 'ok' ],
        [ '18.x',          '19.0.0', 'no' ],
        [ '18.*',          '18.9.9', 'ok' ],
        [ '18.*',          '19.0.0', 'no' ],
        [ '18.x.x',        '18.0.0', 'ok' ],
        [ '18.x.x',        '19.0.0', 'no' ],
        [ '18.2',          '18.1.9', 'no' ],
        [ '18.2',          '18.2.0', 'ok' ],
        [ '18.2',          '18.2.9', 'ok' ],
        [ '18.2',          '18.3.0', 'no' ],
        [ '18.2.x',        '18.1.9', 'no' ],
        [ '18.2.x',        '18.2.0', 'ok' ],
        [ '18.2.x',        '18.3.0', 'no' ],
        [ '18.2.*',        '18.2.0', 'ok' ],
        [ '18.2.3',        '18.2.2', 'no' ],
        [ '18.2.3',        '18.2.3', 'ok' ],
        [ '18.2.3',        '18.2.4', 'no' ],
        [ '=18.2.3',       '18.2.2', 'no' ],
        [ '=18.2.3',       '18.2.3', 'ok' ],
        [ '=18.2.3',       '18.2.4', 'no' ],
        [ 'v18.2.3',       '18.2.2', 'no' ],
        [ 'v18.2.3',       '18.2.3', 'ok' ],
        [ 'v18.2.3',       '18.2.4', 'no' ],
        [ '>=18',          '17.9.9', 'no' ],
        [ '>=18',          '18.0.0', 'ok' ],
        [ '>=18',          '18.9.9', 'ok' ],
        [ '>=18.2',        '18.1.9', 'no' ],
        [ '>=18.2',        '18.2.0', 'ok' ],
        [ '>=18.2.3',      '18.2.2', 'no' ],
        [ '>=18.2.3',      '18.2.3', 'ok' ],
        [ '>18',           '18.9.9', 'no' ],
        [ '>18',           '19.0.0', 'ok' ],
        [ '>18.2',         '18.2.9', 'no' ],
        [ '>18.2',         '18.3.0', 'ok' ],
        [ '>18.2.3',       '18.2.3', 'no' ],
        [ '>18.2.3',       '18.2.4', 'ok' ],
        [ '<18',           '17.9.9', 'ok' ],
        [ '<18',           '18.0.0', 'no' ],
        [ '<18.2',         '18.1.9', 'ok' ],
        [ '<18.2',         '18.2.0', 'no' ],
        [ '<18.2.3',       '18.2.2', 'ok' ],
        [ '<18.2.3',       '18.2.3', 'no' ],
        [ '<=18',          '18.9.9', 'ok' ],
        [ '<=18',          '19.0.0', 'no' ],
        [ '<=18.2',        '18.2.9', 'ok' ],
        [ '<=18.2',        '18.3.0', 'no' ],
        [ '<=18.2.3',      '18.2.3', 'ok' ],
        [ '<=18.2.3',      '18.2.4', 'no' ],
        [ '^18',           '18.0.0', 'ok' ],
        [ '^18',           '18.9.9', 'ok' ],
        [ '^18',           '19.0.0', 'no' ],
        [ '^18.2',         '18.1.9', 'no' ],
        [ '^18.2',         '18.2.0', 'ok' ],
        [ '^18.2',         '18.9.9', 'ok' ],
        [ '^18.2',         '19.0.0', 'no' ],
        [ '^18.2.3',       '18.2.2', 'no' ],
        [ '^18.2.3',       '18.2.3', 'ok' ],
        [ '^18.2.3',       '18.9.9', 'ok' ],
        [ '^18.2.3',       '19.0.0', 'no' ],
        [ '~18',           '18.0.0', 'ok' ],
        [ '~18',           '18.9.9', 'ok' ],
        [ '~18',           '19.0.0', 'no' ],
        [ '~18.2',         '18.1.9', 'no' ],
        [ '~18.2',         '18.2.0', 'ok' ],
        [ '~18.2',         '18.2.9', 'ok' ],
        [ '~18.2',         '18.3.0', 'no' ],
        [ '~18.2.3',       '18.2.2', 'no' ],
        [ '~18.2.3',       '18.2.3', 'ok' ],
        [ '~18.2.3',       '18.2.9', 'ok' ],
        [ '~18.2.3',       '18.3.0', 'no' ],
        [ '>= 18',         '17.9.9', 'no' ],
        [ '>= 18',         '18.0.0', 'ok' ],
        [ '>=18 <21',      '18.0.0', 'ok' ],
        [ '>=18 <21',      '20.9.9', 'ok' ],
        [ '>=18 <21',      '21.0.0', 'no' ],
        [ '18 || >=20',    '18.5.0', 'ok' ],
        [ '18 || >=20',    '19.0.0', 'no' ],
        [ '18 || >=20',    '20.0.0', 'ok' ],
        [ '^20.19.0 || >=22.12.0', '20.18.1', 'no' ],
        [ '^20.19.0 || >=22.12.0', '20.19.0', 'ok' ],
        [ '^20.19.0 || >=22.12.0', '21.7.0', 'no' ],
        [ '^20.19.0 || >=22.12.0', '22.11.0', 'no' ],
        [ '^20.19.0 || >=22.12.0', '22.12.0', 'ok' ],
        [ '>=18.18.0',     '18.17.9', 'no' ],
        [ '>=18.18.0',     '18.18.0', 'ok' ],
    );
    for my $case (@cases) {
        is( Cpanel::API::UserTools::_node_range_satisfies( $case->[0], $case->[1] ),
            $case->[2], "$case->[0] against $case->[1]" );
    }
};

subtest 'unknown forms reject the whole range' => sub {
    my @cases = (
        '^0.2.3', '~0.2', '^0', '~0',
        '18.2 - 20.0', '18.2.3-beta', '18.2.3+build', '~>18',
        '>=x', '>=18.x', '18.x.3', '18.2.3.4',
        '^18 ||', '|| ^18', '=18', 'v18.2',
        'latest', 'lts/*', 'workspace:*', 'https://example.test/node',
        '1234567', '1234567.0.0',
        ( '18 ' x 65 ),
    );
    for my $range (@cases) {
        is( Cpanel::API::UserTools::_node_range_satisfies( $range, '18.2.3' ),
            'unknown', "unknown form: $range" );
    }
    my $eight = join ' || ', ('18') x 8;
    is( Cpanel::API::UserTools::_node_range_satisfies( $eight, '18.0.0' ),
        'ok', 'eight alternatives accepted' );
    my $nine = join ' || ', ('18') x 9;
    is( Cpanel::API::UserTools::_node_range_satisfies( $nine, '18.0.0' ),
        'unknown', 'nine alternatives rejected' );
    is( Cpanel::API::UserTools::_node_range_satisfies( '^18 || ^0.2.3', '18.0.0' ),
        'unknown', 'one unknown alternative poisons the match' );
};

subtest 'node --version reader' => sub {
    my $home = tempdir( CLEANUP => 1 );
    my $bin = write_node_script( "$home/good", "printf 'v24.22.2\\n'" );
    is( Cpanel::API::UserTools::_node_bin_version($bin), '24.22.2',
        'real version parsed' );
    for my $bad ( '24.22.2', 'v24.22', 'v24.22.2 extra', 'v24.22.2.1' ) {
        my $script = write_node_script( "$home/bad-" . length($bad),
            "printf '$bad\\n'" );
        is( Cpanel::API::UserTools::_node_bin_version($script), undef,
            "unreadable version $bad" );
    }
    my $failed = write_node_script( "$home/failed", 'exit 1' );
    is( Cpanel::API::UserTools::_node_bin_version($failed), undef,
        'non-zero exit is unreadable' );
    my $slow = write_node_script( "$home/slow", "sleep 2; printf 'v24.22.2\\n'" );
    local $Cpanel::API::UserTools::NODE_VERSION_TIMEOUT = 1;
    is( Cpanel::API::UserTools::_node_bin_version($slow), undef,
        'timed-out version is unreadable' );
};

subtest 'binary selection' => sub {
    my $home = tempdir( CLEANUP => 1 );
    my $app  = "$home/app";
    my ( $bin, $source, $warning, $note );

    # No engines: newest, and not a single node --version spawn.
    my $marker26 = "$home/marker26";
    my $marker24 = "$home/marker24";
    add_node( $home, 'ea', 26, "printf ran > '$marker26'; printf 'v26.13.0\\n'" );
    add_node( $home, 'ea', 24, "printf ran > '$marker24'; printf 'v24.22.2\\n'" );
    write_package( $app, '{"name":"plain"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs26/, 'no engines picks the newest major' );
    is( $warning, undef, 'no engines has no warning' );
    is( $note,    undef, 'no engines has no note' );
    ok( !-e $marker26 && !-e $marker24, 'no engines spawns no node' );

    # >=18 with 18 and 24 installed: 24 is the newest that fits.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    add_node( $home, 'ea', 18, "printf 'v18.20.0\\n'" );
    add_node( $home, 'ea', 24, "printf 'v24.22.2\\n'" );
    write_package( $app, '{"engines":">=18"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs24/, '>=18 builds on 24 when 18 and 24 exist' );
    is( $warning, undef, 'matching range has no warning' );
    is( $note, 'Node 24.22.2 fits this app\'s package.json (>=18).',
        'matching range names the version and range' );

    # >=24 <26: 26 is newest but does not fit; 24 does.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    add_node( $home, 'ea', 26, "printf 'v26.13.0\\n'" );
    add_node( $home, 'ea', 24, "printf 'v24.22.2\\n'" );
    write_package( $app, '{"engines":">=24 <26"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs24/, 'compound range selects the fitting older major' );
    is( $warning, undef, 'fitting older major has no warning' );
    like( $note, qr/fits.*\(\>=24 <26\)/, 'compound range note' );

    # The alternative range selects the newest that satisfies the second arm.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    add_node( $home, 'ea', 22, "printf 'v22.11.0\\n'" );
    add_node( $home, 'ea', 20, "printf 'v20.18.1\\n'" );
    add_node( $home, 'ea', 24, "printf 'v24.22.2\\n'" );
    write_package( $app, '{"engines":"^20.19.0 || >=22.12.0"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs24/, 'alternative range picks the newest fit' );
    is( $warning, undef, 'alternative range has no warning' );

    # Nothing fits: warning, still returns the newest binary.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    add_node( $home, 'ea', 26, "printf 'v26.13.0\\n'" );
    add_node( $home, 'ea', 24, "printf 'v24.22.2\\n'" );
    write_package( $app, '{"engines":">=99"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs26/, 'no match still returns the newest binary' );
    like( $warning,
        qr/asks for Node >=99, but no installed version matches.*Node 26\.13\.0/,
        'no match warning names the range and version' );
    is( $note, undef, 'warning and note are not both returned' );

    # Unknown range: one spawn, cannot-tell note, range never echoed.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    add_node( $home, 'ea', 26, "printf 'v26.13.0\\n'" );
    write_package( $app, '{"engines":"workspace:*"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs26/, 'unknown range still returns the newest binary' );
    is( $warning, undef, 'unknown range has no warning' );
    like( $note, qr/^Cannot tell whether Node 26\.13\.0 fits this app's package\.json\.$/,
        'unknown range note names the real version' );
    unlike( $note, qr/workspace/, 'unknown range is not echoed' );

    # Same major in both families: existing family order wins the tie.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    add_node( $home, 'ea',  24, "printf 'v24.1.0\\n'" );
    add_node( $home, 'alt', 24, "printf 'v24.9.0\\n'" );
    write_package( $app, '{"engines":">=18"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr{/cpanel/ea-nodejs24/}, 'same major prefers the first family' );

    # Unreadable newer binary with no readable match: newest unreadable.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    add_node( $home, 'ea', 26, 'exit 1' );
    add_node( $home, 'ea', 24, "printf 'v24.22.2\\n'" );
    write_package( $app, '{"engines":">=99"}' );
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs26/, 'unreadable newest is selected when nothing fits' );
    is( $warning, undef, 'unreadable is not a mismatch warning' );
    is( $note, 'Cannot tell whether Node 26 fits this app\'s package.json.',
        'unreadable note uses the folder major' );

    # Timed-out newest: stop spawning, mark the rest unreadable, no warning.
    $home = tempdir( CLEANUP => 1 );
    $app  = "$home/app";
    my $marker = "$home/later-ran";
    add_node( $home, 'ea', 26, "sleep 2; printf 'v26.13.0\\n'" );
    add_node( $home, 'ea', 24, "printf ran > '$marker'; printf 'v24.22.2\\n'" );
    write_package( $app, '{"engines":">=99"}' );
    local $Cpanel::API::UserTools::NODE_VERSION_TIMEOUT = 1;
    ( $bin, $source, $warning, $note ) =
      Cpanel::API::UserTools::_select_node_for_app( $app, "$home/cpanel", "$home/alt" );
    like( $bin, qr/ea-nodejs26/, 'timed-out binary is selected' );
    is( $warning, undef, 'timed-out binary never produces the warning' );
    is( $note, 'Cannot tell whether Node 26 fits this app\'s package.json.',
        'timed-out note uses the folder major' );
    ok( !-e $marker, 'later binaries are not spawned after a timeout' );
};

done_testing();
