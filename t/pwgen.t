use Test::More qw( no_plan );
use Data::Pwgen;

foreach my $i ( 1 .. 100 ) {
    my $pw = Data::Pwgen::pwgen($i);
    is( length($pw), $i, 'PW length is ' . $i );
    my $strength = Data::Pwgen::strength($pw);
    my $ts       = $i - 8;
    cmp_ok( $strength, '>=', $ts, 'Strengh is ok' );
}

my $pw = Data::Pwgen::pwgen( 16, 'nums' );
ok( $pw =~ m/^\d{16}$/, 'PW (' . $pw . ') contains only numbers' );
$pw = Data::Pwgen::pwgen( 16, 'lower' );
ok( $pw =~ m/^[a-z]{16}$/, 'PW (' . $pw . ') contains only lower-case chars' );
