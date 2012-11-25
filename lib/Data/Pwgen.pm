package Data::Pwgen;
# ABSTRACT: simple password generation and assessment

use warnings;
use strict;
use 5.008;

=head1 NAME

Data::Pwgen - Password generation and assessment

=head1 SYNOPSIS

    use Data::Pwgen;
    my $pass = &Data::Pwgen::pwgen(12);
    my $str = &Data::Pwgen::strength($pass);

=head1 DESCRIPTION

This is a simple module that implements generation and assesment of secure passwords.

=cut

{
## no critic (ProhibitNoisyQuotes)
    my %rep = (
        'nums'  => [ '0' .. '9' ],
        'signs' => [ '%', '$', '_', '-', '+', '*', '&', '/', '=', '!', '#' ],
        'lower' => [ 'a' .. 'z' ],
        'upper' => [ 'A' .. 'Z' ],
    );
## use critic
    $rep{'chars'}    = [ @{ $rep{'lower'} },    @{ $rep{'upper'} } ];
    $rep{'alphanum'} = [ @{ $rep{'chars'} },    @{ $rep{'nums'} } ];
    $rep{'alphasym'} = [ @{ $rep{'alphanum'} }, @{ $rep{'signs'} } ];
    my $entropy = 0;

    ## no critic (ProhibitMagicNumbers)
    my $default_length = 16;
    my $min_length = 8;
    ## use critic

=func pwgen

Generate a passwort with the (optional) given length and (also optional) given character class.

=cut
    sub pwgen {
        my $length = shift || $default_length;
        my $class  = shift || 'alphanum';
        $rep{$class} or $class = 'alphanum';
        $entropy++;
        srand( time() + $entropy );
        my $pw = join( q{}, map { $rep{$class}[ rand( $#{ $rep{$class} } ) ] } 0 .. $length - 1 );
        return $pw;
    }

=func strength

Returns a numeric rating of the quality of the supplied (password) string.

=cut
    sub strength {
        my $pw       = shift;
        my $strength = 0;
        $strength += length($pw) - ($min_length+1);
        $strength++ if ( $pw =~ m/[a-z]/ );         # lower case alpha
        $strength++ if ( $pw =~ m/[A-Z]/ );         # upper case alpha
        $strength++ if ( $pw =~ m/[0-9]/ );         # numbers
        $strength++ if ( $pw =~ m/[^A-Z0-9]/i );    # non-alphanums
        return $strength;
    }
}

1; # End of Data::Pwgen
