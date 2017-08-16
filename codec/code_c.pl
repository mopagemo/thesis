#!/usr/bin/perl

=head1 NAME

code_c.pl - Encrypts and decrypts messages with algorithm Code C1

=head1 SYNOPSIS

    ./code_c.pl --mode encrypt --plain HANSPLOETZLICHSCHWERERKRANKTERWIN --key spekulation --fill 2

    ./code_c.pl --mode encrypt --plain HANSPLOETZLICHSCHWERERKRANKTERWIN --key spekulation --fill 2 --format fiver

    ./code_c.pl --mode decrypt --cipher jmaugdtsfyxhmzkzglbtoybpxgrcuviswexatidnufuxhqekn --key spekulation --fill 2

=head1 DESCRIPTION

Encrypt and decrypt messages with the algorithm Code C1, as developed by the
Ministerium fuer Staatssicherheit (MfS) in the GDR. It uses a combination of
letter substitution and columnar transposition, as well as fill characters.

=head2 Options

=over

=item --mode encrypt

Should be C<encrypt> or C<decrypt>.

=item --plain foo

Plain text to be encrypted.

=item --cipher bar

Cipher text to be decrypted.

=item --key baz

Secret key used for encryption.

=item --fill 2

Adds a fill character after every n'th character (in this after every second
character).

=item --nosub

Don't perform the substitution step.

=item --format plain

Output format. Can be C<plain> (default) or C<fiver> for groups of five
characters.

=back

=cut

use warnings;
use strict;

use Data::Dumper;
use Array::Shuffle qw(shuffle_array);
use POSIX;

no warnings 'experimental::smartmatch';

use Getopt::Long;

my %cmdline;
my $result;

Getopt::Long::GetOptions(
    "mode=s"   => \$cmdline{'mode'},
    "plain=s"  => \$cmdline{'plain'},
    "cipher=s" => \$cmdline{'cipher'},
    "key=s"    => \$cmdline{'key'},
    "format=s" => \$cmdline{'format'},
    "fill=i"   => \$cmdline{'fill'},
    "nosub"    => \$cmdline{'nosub'}
);

if ( $cmdline{'mode'} eq 'encrypt' ) {
    die "Need a key"                   unless $cmdline{'key'};
    die "Need a plain text to encrypt" unless $cmdline{'plain'};

    $result = encrypt( $cmdline{'key'}, $cmdline{'plain'}, $cmdline{'fill'}, $cmdline{'nosub'} );
} elsif ( $cmdline{'mode'} eq 'decrypt' ) {
    die "Need a key or score dictionary" if not $cmdline{'key'};
    die "Need a cipher text to decrypt" unless $cmdline{'cipher'};

    $result = decrypt( $cmdline{'key'}, $cmdline{'cipher'}, $cmdline{'fill'}, $cmdline{'nosub'} );
}

if ($result) {
    if ( $cmdline{'format'} and $cmdline{'format'} eq 'fiver' ) {
        print output_five_groups($result);
        print "\n";
    } else {
        print "$result\n";
    }
}

=head1 INTERNAL METHODS

=over

=item encrypt

Encrypt given text with a key and a number of fill characters.

=cut

sub encrypt {
    my $key   = shift;
    my $plain = shift;
    my $fill  = shift;
    my $nosub = shift;

    $plain = lc($plain);
    $plain =~ s/[^a-z]//g;

    my @plain_arr = split( '', $plain );

    my $numeric_key = convert_key_numerical($key);
    my $box_length  = scalar @$numeric_key;

    my $sub_plain;

    if ($nosub) {
        $sub_plain = \@plain_arr;
    } else {
        my $sub_table = create_sub_table($key);
        $sub_plain = substitute_text( $sub_table, \@plain_arr );
    }

    my $box = sort_box( $box_length, $numeric_key, $sub_plain );

    my $transposed = join_text_encrypt( $box_length, $box );

    my $filled = add_filler( $fill, $transposed );

    my $cipher = array_to_string($filled);

    return $cipher;
}

=item decrypt

Reverse the encryption process of Code A.

=cut

sub decrypt {
    my $key    = shift;
    my $cipher = shift;
    my $fill   = shift;
    my $nosub  = shift;

    $cipher = lc($cipher);
    $cipher =~ s/[^a-z]//g;

    my @cipher = split( '', $cipher );

    my $sub_cipher = remove_filler( $fill, \@cipher );

    my $numeric_key = convert_key_numerical($key);
    my $box_length  = scalar @$numeric_key;
    my $key_lookup  = key_lookup( $box_length, $numeric_key );

    my $box = fill_box_decrypt( $box_length, $key_lookup, $sub_cipher );

    my $sub_plain;

    if ($nosub) {
        $sub_plain = $box;
    } else {
        my $sub_table = reverse_sub( create_sub_table($key) );
        $sub_plain = substitute_text( $sub_table, $box );
    }

    my $plain = array_to_string($sub_plain);

    return $plain;
}

=item array_to_string

Turns an array of characters into a string.

=cut

sub array_to_string {
    my $arr = shift;
    my $str = '';

    foreach my $l (@$arr) {
        $str .= $l if $l;
    }

    return $str;
}

=item add_filler

Add fill characters from unused characters to even out character distribution.
If all are used up, uses just fillers from A to Z.

=cut

sub add_filler {
    my $fill = shift;
    my $text = shift;

    return $text unless $fill;

    my @filler      = ();
    my @filled_text = ();

    foreach my $l ( 'a' .. 'z' ) {
        if ( not $l ~~ @$text ) {
            push( @filler, $l );
        }
    }

    if ( scalar @filler == 0 ) {
        warn "All letters used, using fillers a-z";

        # Would be better to use least frequent letters
        @filler = ( 'a' .. 'z' );
    }

    my $filler_count = scalar @filler;
    my $filler_pos   = 0;

    my $i = 0;
    foreach my $l (@$text) {
        push( @filled_text, $l );

        if ( $i % $fill == ( $fill - 1 ) ) {
            push( @filled_text, $filler[ $filler_pos % $filler_count ] );
            $filler_pos++;
        }

        $i++;
    }

    return \@filled_text;
}

=item remove_filler

Removes fill characters from the given text.

=cut

sub remove_filler {
    my $fill = shift;
    my $text = shift;

    return $text unless $fill;

    my @cleaned_text = ();

    my $i = 0;

    foreach my $l (@$text) {
        push( @cleaned_text, $l ) if ( $i % ( $fill + 1 ) != $fill );
        $i++;
    }

    return \@cleaned_text;
}

=item substitute_text

Apply the substitution table to the given text and return the substituted text.

=cut

sub substitute_text {
    my $sub_table = shift;
    my $text      = shift;

    my @subbed = map { $sub_table->{$_} } @$text;

    return \@subbed;
}

=item create_sub_table

Create a substitution lookup (hash) according to the rules of Code C1, with
given key.

=cut

sub create_sub_table {
    my $key = shift;

    $key = lc($key);
    $key =~ s/[^a-z]//g;

    my @key = split( '', $key );

    my %already_used = ();
    my %sub_table = map { $_ => undef } 'a' .. 'z';
    my @sub_table;

    my $last_k = undef;

    foreach my $a ( 'a' .. 'z' ) {
        my $k = shift @key;
        if ( not $k ) {
            $last_k = $a;
            last;
        }

        push( @sub_table, $k );
        $sub_table{$a}    = $k;
        $already_used{$k} = 1;
    }

    my $first_pos = length($key);
    my $last_pos  = 25;
    my $flip      = 0;
    my @order     = ( 'a' .. 'z' );

    foreach my $i ( $first_pos .. $last_pos ) {
        foreach my $k (@order) {
            next if ( $already_used{$k} );

            if ( not $flip ) {
                $sub_table[$first_pos] = $k;
                $sub_table{ $order[$first_pos] } = $k;
                $first_pos++;
            } else {
                $sub_table[$last_pos] = $k;
                $sub_table{ $order[$last_pos] } = $k;
                $last_pos--;
            }

            $already_used{$k} = 1;
            last;
        }

        $flip = not $flip;

    }

    return \%sub_table;
}

=item key_lookup

Creates a key lookup so that we know which character goes into which column
during the decryption process.

=cut

sub key_lookup {
    my $box_length = shift;
    my $key        = shift;

    my @lookup;

    for ( my $i = 0 ; $i < scalar $box_length ; $i++ ) {
        $lookup[ $key->[$i] ] = $i;
    }

    return \@lookup;
}

=item convert_key_numerical

Make the key sortable by converting it to numbers.

=cut

sub convert_key_numerical {
    my $key = shift;

    $key = lc($key);
    $key =~ s/[^a-z]//g;

    my @key = split( '', $key );
    my $i = 0;

    for my $l ( 'a' .. 'z' ) {
        for my $pl (@key) {
            if ( $pl eq $l ) {
                $key =~ s/$l/$i,/;
                $i++;
            }
        }
    }

    chop($key);

    return [ split( ',', $key ) ];
}

=item reverse_sub

Create a reverse substitution lookup table to undo a substitution.

=cut

sub reverse_sub {
    my $table = shift;

    my %reverse_table = map { $table->{$_} => $_ } keys %$table;

    return \%reverse_table;
}

=item fill_box_decrypt

Fills columns and rows with the text for description, according to the key
given.

=cut

sub fill_box_decrypt {
    my $box_length = shift;
    my $key_lookup = shift;
    my $text       = shift;

    my $total_box_chars = scalar(@$text);
    my $height          = ceil( $total_box_chars / $box_length );
    my $long_columns    = $total_box_chars % $box_length;

    my @box = ();

    my $row = 0;
    my $col = 0;

    for ( my $i = 0 ; $i < $total_box_chars ; $i++ ) {
        my $l      = $text->[$i];
        my $to_col = $key_lookup->[$col];

        $box[ $row * $box_length + $to_col ] = $l;

        $row++;

        if ( $row == $height ) {
            $row = 0;
            $col++;
        } elsif ( $long_columns and $to_col >= $long_columns and $row == $height - 1 ) {
            $col++;
            $row = 0;
        }
    }

    return \@box;
}

=item output_box

Utility function for debugging to show the current content of columns and rows.

=cut

sub output_box {
    my $cols = shift;
    my $box  = shift;

    my $total_box_chars = scalar(@$box);

    foreach my $b ( 0 .. ( $total_box_chars - 1 ) ) {
        printf( '%s ', $box->[$b] || ' ' );

        if ( ( $b + 1 ) % $cols == 0 && $b != ( $total_box_chars - 1 ) ) {
            print "\n";
        }
    }

    print "\n";
}

=item sort_box

Sorts columns by the given key.

=cut

sub sort_box {
    my $box_length = shift;
    my $key        = shift;
    my $box        = shift;

    my $total_box_chars = scalar(@$box);

    my @new_box;

    foreach my $i ( 0 .. ( $total_box_chars - 1 ) ) {
        my $col     = $i % $box_length;
        my $row     = int( $i / $box_length );
        my $new_col = $key->[$col];

        $new_box[ $row * $box_length + $new_col ] = $box->[$i];
    }

    return \@new_box;
}

=item join_text_encrypt

Reads out letters column by column into an array of characters.

=cut

sub join_text_encrypt {
    my $box_length = shift;
    my $box        = shift;

    my $total_box_chars = scalar(@$box);
    my $height          = ceil( $total_box_chars / $box_length );

    my @text = ();

    foreach my $i ( 0 .. ( $total_box_chars - 1 ) ) {
        my $col = $i % $box_length;
        my $row = int( $i / $box_length );

        $text[ $col * $height + $row ] = $box->[$i];
    }

    return \@text;
}

=item output_five_groups

Prints given string in groups of 5 characters, separated by space. Prints a
maximum of 5 groups per line.

=cut

sub output_five_groups {
    my $text = shift;

    my $i = 1;
    foreach my $l ( split( '', $text ) ) {
        print uc($l) . ' ';

        if ( $i % 25 == 0 ) {
            print "\n";
        } elsif ( $i % 5 == 0 ) {
            print "  ";
        }

        $i++;
    }
}

=back

=head1 AUTHOR

Moritz Dulies

=head1 COPYRIGHT

Public domain

=cut
