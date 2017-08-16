#!/usr/bin/perl

=encoding utf-8

=head1 NAME

granit.pl - Encrypts and decrypts messages with algorithm GRANIT

=head1 SYNOPSIS

    ./granit.pl --plain "Jeder Zwischenfall bei Unternehmen Edelweiß am 12 März ist möglichst zu vermeiden Bericht bis 1 April" --key1 "gute halten. Ich bin gewiß," --key2 "daß er der feinste Mann" --subkey RHEINAST --mode encrypt --format plain

    ./granit.pl --plain "Jeder Zwischenfall bei Unternehmen Edelweiß am 12 März ist möglichst zu vermeiden Bericht bis 1 April" --key1 "gute halten. Ich bin gewiß," --key2 "daß er der feinste Mann" --subkey RHEINAST --mode encrypt --format fiver

    ./granit.pl --cipher 252328896745926173318686481668778243816007408362876236802722817921820306193121178827823878026111299899926083737993082598824931628214235 --key1 "gute halten. Ich bin gewiß," --key2 "daß er der feinste Mann" --subkey RHEINAST --mode decrypt

=head1 DESCRIPTION

Encrypt and decrypt messages with the algorithm GRANIT, as developed by the
Ministerium für Staatssicherheit (MfS) in the GDR. It uses a combination of
letter substitution and columnar transposition, as well as fill characters.

=head2 Options

=over

=item --mode encrypt

Should be C<encrypt> or C<decrypt>.

=item --plain foo

Plain text to be encrypted as a command line option.

=item --plainfile foo.txt

File name of plain text to be encrypted.

=item --cipher bar

Cipher text to be decrypted as a command line option.

=item --cipherfile bar.txt

File name of cipher text to be decrypted.

=item --key1 baz

First secret key used for encrypting and decrypting.

=item --key2 baz

Second secret key used for encrypting and decrypting (both are needed).

=item --subkey bax

Secret key used for the character substitution.

=item --debug

Output the state of the encryption or decryption after each step.

=item --format plain

Output format. Can be C<plain> (default) or C<fiver> for groups of five
characters.

=back

=cut

use warnings;
use strict;

no warnings 'experimental::smartmatch';

use Getopt::Long;
use Data::Dumper;
use POSIX;
use File::Slurp;
use List::Util qw(shuffle);

my %cmdline;
my $result;

Getopt::Long::GetOptions(
    "mode=s"       => \$cmdline{'mode'},
    "plain=s"      => \$cmdline{'plain'},
    "plainfile=s"  => \$cmdline{'plainfile'},
    "cipher=s"     => \$cmdline{'cipher'},
    "cipherfile=s" => \$cmdline{'cipherfile'},
    "subkey=s"     => \$cmdline{'subkey'},
    "key1=s"       => \$cmdline{'key1'},
    "key2=s"       => \$cmdline{'key2'},
    "debug"        => \$cmdline{'debug'},
    "format=s"     => \$cmdline{'format'}
);

if ( not $cmdline{'mode'} ) {
    die "Missing --mode encrypt|decrypt";
} elsif ( $cmdline{'mode'} eq 'encrypt' ) {
    die "Need a key" unless $cmdline{'key1'} and $cmdline{'key2'};

    if ( $cmdline{'plainfile'} ) {
        $cmdline{'plain'} = read_file( $cmdline{'plainfile'} );
    }

    die "Need a plain text to encrypt" unless $cmdline{'plain'};

    $result = encrypt( $cmdline{'subkey'}, $cmdline{'key1'}, $cmdline{'key2'}, $cmdline{'plain'}, $cmdline{'debug'} );
} elsif ( $cmdline{'mode'} eq 'decrypt' ) {
    die "Need a key" unless $cmdline{'key1'} and $cmdline{'key2'};

    if ( $cmdline{'cipherfile'} ) {
        $cmdline{'cipher'} = read_file( $cmdline{'cipherfile'} );
    }

    die "Need a cipher text to decrypt" unless $cmdline{'cipher'};

    $result = decrypt( $cmdline{'subkey'}, $cmdline{'key1'}, $cmdline{'key2'}, $cmdline{'cipher'}, $cmdline{'debug'} );
} else {
    die "Invalid cipher mode";
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

Method to (unsurprisingly) do the actual encryption.

=cut

sub encrypt {
    my ( $subkey, $key1, $key2, $plain, $debug ) = @_;

    $plain  = prepare_plain($plain);
    $subkey = prepare_key($subkey);
    $key1   = prepare_key($key1);
    $key2   = prepare_key($key2);

    check_keys( $key1, $key2 );

    if ($debug) {
        print "Key 1: $key1\nKey 2: $key2\nSubstitution key: $subkey\n";
        print "Prepared plain:\n$plain\n";
    }

    $plain = letters_to_numbers( $subkey, $plain );

    if ($debug) {
        print "After substitution:\n";
        print array_to_string($plain) . "\n";
    }

    my $numeric_key1 = convert_key_numerical($key1);
    my $box_length1  = scalar @$numeric_key1;
    my $numeric_key2 = convert_key_numerical($key2);
    my $box_length2  = scalar @$numeric_key2;

    my $box = fill_box_encrypt( $box_length1, $plain );

    if ($debug) {
        print "Box before transposition:\n";
        output_box( $box_length1, $box );
    }

    $box = sort_box( $box_length1, $numeric_key1, $box );

    if ($debug) {
        print "Box after sorting with first key:\n";
        output_box( $box_length1, $box );
    }

    my $joined = join_text_encrypt( $box_length1, $box );

    $box = fill_box_encrypt( $box_length2, $joined );

    if ($debug) {
        print "Box after filling up to new key:\n";
        output_box( $box_length2, $box );
    }

    $box = sort_box( $box_length2, $numeric_key2, $box );

    if ($debug) {
        print "Box after sorting with second key:\n";
        output_box( $box_length2, $box );
    }

    my $final = join_text_encrypt( $box_length2, $box );
    my $ciphertext = array_to_string($final);

    return $ciphertext;
}

=item decrypt

Method to (unsurprisingly) do the actual decryption.

=cut

sub decrypt {
    my ( $subkey, $key1, $key2, $cipher, $debug ) = @_;

    $cipher = prepare_cipher($cipher);
    $subkey = prepare_key($subkey);
    $key1   = prepare_key($key1);
    $key2   = prepare_key($key2);

    if ($debug) {
        print "Key 1: $key1\nKey 2: $key2\nSubstitution key: $subkey\n";
        print "Prepared cipher:\n " . array_to_string($cipher) . "\n";
    }

    my $numeric_key1 = convert_key_numerical($key1);
    my $box_length1  = scalar @$numeric_key1;
    my $numeric_key2 = convert_key_numerical($key2);
    my $box_length2  = scalar @$numeric_key2;

    my $key_lookup1 = key_lookup( $box_length1, $numeric_key1 );
    my $key_lookup2 = key_lookup( $box_length2, $numeric_key2 );

    my $box = fill_box_decrypt( $box_length2, $key_lookup2, $cipher );

    if ($debug) {
        print "Box after filling up and sorting second key:\n";
        output_box( $box_length2, $box );
    }

    $box = fill_box_decrypt( $box_length1, $key_lookup1, $box );

    if ($debug) {
        print "Box after filling up and sorting first key:\n";
        output_box( $box_length1, $box );
    }

    return numbers_to_letters( $subkey, array_to_string($box) );
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

=item fill_box_encrypt

Fills columns and rows with the text for encryption.

=cut

sub fill_box_encrypt {
    my ( $box_length, $text ) = @_;

    my $total_box_chars = scalar(@$text);
    my $height          = ceil( $total_box_chars / $box_length );
    my $long_columns    = $total_box_chars % $box_length;

    my @box = ();

    my $row = 0;
    my $col = 0;

    for ( my $i = 0 ; $i < $total_box_chars ; $i++ ) {
        $box[$i] = $text->[$i];
    }

    return \@box;
}

=item fill_box_decrypt

Fills columns and rows with the text for decryption, according to the key given.

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
    my ( $cols, $box ) = @_;

    my $total_box_chars = scalar(@$box);

    foreach my $b ( 0 .. ( $total_box_chars - 1 ) ) {
        printf( '%s ', defined $box->[$b] ? $box->[$b] : ' ' );

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
    my ( $box_length, $key, $box ) = @_;

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

    @text = grep { defined $_ } @text;

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
        print uc($l);

        if ( $i % 5 == 0 ) {
            print " ";
        }

        $i++;
    }
}

=item numbers_to_letters

Turns numbers into letters or other characters, taking the number signal into
account. Warns and returns undef for implausible number texts.

=cut

sub numbers_to_letters {
    my ( $sub_key, $text ) = @_;

    if ( $text =~ /[0-7](8|9)$/ ) {
        warn $text;
        warn "Impossible plaintext (ending on 8 or 9 without prececing 8 or 9)";
        return undef;
    }

    my @letters;
    my @numbers;

    my @alphabet =
        ( 0, 1, 2, 3, 4, 5, 6, 7, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99 );
    my @default_map = ( 'a' .. 'i', 'k' .. 'z', '_', '.', ',' );

    my %map = ();

    foreach my $i ( 0 .. scalar @alphabet - 1 ) {
        $map{ $alphabet[$i] } = $default_map[$i];
    }

    if ($sub_key) {
        my $i = 0;
        my @letters_used;

        %map = ();

        foreach my $k ( split( '', lc($sub_key) ) ) {
            $map{ $alphabet[$i] } = $k;
            push( @letters_used, $k );
            $i++;
        }

        foreach my $k ( 'a' .. 'i', 'k' .. 'z' ) {
            last if ( $i >= scalar @alphabet );
            next if ( $k ~~ @letters_used );

            $map{ $alphabet[$i] } = $k;
            $i++;
        }

        $map{'98'} = '.';
        $map{'99'} = ',';
    }

    my $sz_count = 0;

    while ( length $text > 0 ) {
        if ( $text =~ /^((8|9)\d)/ ) {
            if ( $1 != 97 and $sz_count % 2 != 0 ) {
                push( @letters, $2 );
                push( @numbers, $2 );
                $text =~ s/\d//;
            } else {
                push( @letters, $map{$1} ) unless ( $1 == 97 );
                push( @numbers, $1 );

                if ( $1 == 97 ) {
                    $sz_count++;
                }

                $text =~ s/\d\d//;
            }
        } else {
            if ( $sz_count % 2 != 0 ) {
                push( @letters, substr( $text, 0, 1 ) );
            } else {
                push( @letters, $map{ substr( $text, 0, 1 ) } );
            }

            push( @numbers, substr( $text, 0, 1 ) );
            $text =~ s/\d//;
        }
    }

    if ( $sz_count % 2 != 0 ) {
        warn "Impossible plaintext (sz count)";
        return undef;
    }

    my $letter_text = join( '', @letters );

    if (   $letter_text =~ /,,/
        or $letter_text =~ /,\./
        or $letter_text =~ /\.,/
        or $letter_text =~ /__/
        or $letter_text =~ /\.\./
        or $letter_text =~ /,$/ )
    {
        warn "Unlikely punction";
        return undef;
    }

    if ( $sz_count > 0 ) {
        my $copy = $letter_text;

        if ( $copy !~ /(111|222|333|444|555|666|777|888|999)/ ) {
            warn "Number signal but no numbers";
            return undef;
        }

        $copy =~ s/(111|222|333|444|555|666|777|888|999)//g;
        if ( $copy =~ /\d/ ) {
            warn "Numbers still present, but they are not tripled";
            return undef;
        }

        $letter_text =~ s/$_$_$_/$_/g for ( 0 .. 9 );
    }

    return $letter_text;
}

=item letters_to_numbers

Turns letters and special characters into numbers for encryption. Handles the
number signal conversion.

=cut

sub letters_to_numbers {
    my ( $subkey, $plain ) = @_;

    my @alphabet =
        ( 0, 1, 2, 3, 4, 5, 6, 7, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99 );
    my @default_map = ( 'a' .. 'i', 'k' .. 'z', '_', '.', ',' );

    my %map = ();

    foreach my $number (@alphabet) {
        if ( length $subkey > 0 ) {
            my $letter = substr( $subkey, 0, 1 );

            $subkey = substr( $subkey, 1 );

            if ( not defined $map{$letter} ) {
                $map{$letter} = $number;
                next;
            }
        }

        foreach my $letter (@default_map) {
            next if ( defined $map{$letter} );

            $map{$letter} = $number;
            last;
        }
    }

    my @output;
    my $number_mode_on = 0;

    foreach my $plain_letter ( split( '', $plain ) ) {
        if ( $plain_letter =~ /\d/ ) {
            if ( not $number_mode_on ) {

                # Split because mapped character might have 2 digits
                push( @output, split( '', $map{'_'} ) );
                $number_mode_on = 1;
            }

            push( @output, $plain_letter );
            push( @output, $plain_letter );
            push( @output, $plain_letter );
        } elsif ($number_mode_on) {
            push( @output, split( '', $map{'_'} ) );
            $number_mode_on = 0;

            # Split because mapped character might have 2 digits
            push( @output, split( '', $map{$plain_letter} ) );
        } else {

            # Split because mapped character might have 2 digits
            push( @output, split( '', $map{$plain_letter} ) );
        }
    }

    return \@output;
}

=item cleanup_input

Remove German umlauts according to the description of GRANIT. Lowercases
everything and removes characters that can't be encrypted.

=cut

sub cleanup_input {
    my ($plain) = @_;

    # Convert to lowercase
    $plain = lc($plain);

    # Replace German characters that can't be encrypted
    $plain =~ s/ä/ae/g;
    $plain =~ s/ö/oe/g;
    $plain =~ s/ü/ue/g;
    $plain =~ s/ß/ss/g;
    $plain =~ s/j/ii/g;

    # Remove characters that can't be encrypted
    $plain =~ s/[^a-z0-9.,]//g;

    return $plain;
}

=item prepare_key

Prepares encryption key by calling C<cleanup_input> and additionally removing
commands and periods.

=cut

sub prepare_key {
    my ($key) = @_;

    $key = cleanup_input($key);

    # Keys can't have comma or periods
    $key =~ s/[^a-z0-9]//g;

    return $key;
}

=item prepare_plain

Really just an alias for C<cleanup_input>.
=cut

sub prepare_plain {
    my ($plain) = @_;

    $plain = cleanup_input($plain);

    return $plain;
}

=item prepare_cipher

Prepares ciphertext by calling C<cleanup_input> and additionally removing
anything that isn't a number. Returns reference to array, one character as each
element.

=cut

sub prepare_cipher {
    my ($cipher) = @_;

    # Remove anything that isn't a digit
    $cipher =~ s/[^\d]//g;

    return [ split '', $cipher ];
}

=item array_to_string

Turns an array of characters into a string.

=cut

sub array_to_string {
    my $arr = shift;
    my $str = '';

    foreach my $l (@$arr) {
        $str .= $l if defined $l;
    }

    return $str;
}

=item check_keys

Sanity test, make sure that encryption keys are at least 15 characters long.

=cut

sub check_keys {
    my ( $key1, $key2 ) = @_;

    if ( length $key1 < 15 ) {
        print STDERR "Key 1 should be at least 15 characters long!\n";
    }
    if ( length $key2 < 15 ) {
        print STDERR "Key 2 should be at least 15 characters long!\n";
    }
}

=back

=head1 AUTHOR

Moritz Dulies

=head1 COPYRIGHT

Public domain

=cut
