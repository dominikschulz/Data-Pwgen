package Data::Pwgen;
# ABSTRACT: simple password generation and assessment

use warnings;
use strict;
use 5.008;

use parent 'Exporter';

our @EXPORT_OK = qw(pwgen pwstrength);

=head1 SYNOPSIS

  use Data::Pwgen qw(pwgen pwstrength);
  my $pass = pwgen(12);
  my $str  = pwstrength($pass);

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

=func pwgen($length, $charclass)

Generate a password with the (optional) given length and (also optional) given character class.
The default length is 16. If specified, the character class must be one of the following:

=over 4

=item lower

Lower-case letters.

=item upper

Upper-case letters.

=item chars

Lower- and upper-case letters.

=item nums

The digits 0 through 9.

=item signs

The following characters: % $ _ - + * & / = ! #

=item alphanum

Lower- and upper-case letters and digits.

=item alphasym

I<alphanum> plus I<signs>.

=back

If you pass anything other than one of the above, it will fall back to the default,
which is I<alphanum>.

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

=func pwstrength

Returns a numeric rating of the quality of the supplied (password) string.

=cut

    sub pwstrength {
        my $pw       = shift;
        my $strength = 0;
        $strength += length($pw) - ($min_length+1);
        $strength++ if ( $pw =~ m/[a-z]/ );         # lower case alpha
        $strength++ if ( $pw =~ m/[A-Z]/ );         # upper case alpha
        $strength++ if ( $pw =~ m/[0-9]/ );         # numbers
        $strength++ if ( $pw =~ m/[^A-Z0-9]/i );    # non-alphanums
        return $strength;
    }

=func strength

An alias for pwstrength(), retained for backwards compatibility.
At some point this alias will go away.

=cut

    *strength = \&pwstrength;
}

=head1 SEE ALSO

The following modules provide similar capabilities:
L<App::Genpass>,
L<Crypt::GeneratePassword>, L<String::Random>, L<Data::Random>, L<String::MkPasswd>.

L<http://neilb.org/reviews/passwords.html>: a review of CPAN modules for generating passwords.

=cut

1; # End of Data::Pwgen
