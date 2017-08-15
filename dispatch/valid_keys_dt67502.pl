#!/usr/bin/perl

=head1 NAME

valid_keys_dt67502.pl - counts the number of valid keys for encryption algorithm
DT 67502

=head1 SYNOPSIS

    ./valid_keys_dt67502.pl

    ./valid_keys_dt67502.pl 4

=head1 DESCRIPTION

Counts (by brute force) the number of valid keys for the DT 67502 algorithm
as used in the GDR. It also counts the number of invalid keys and compares
which percentage is valid.

This script only runs for a small number of columns but proves that there is
a relatively low number of actual valid keys.

Tests column widths from 1 to 10, although you're unlikely to get a result for
5 or higher. No attempt was made to make this performant.

=cut

use warnings;
use strict;

use Scalar::Util qw(looks_like_number);


# Create list of valid section numbers
my %valid_keys = ();
for(my $i = 0; $i < 100; $i++) {
    my ($a, $b) = split('', sprintf('%02d', $i));
    next if($a == $b);
    $valid_keys{$a . ''} = 1;
    $valid_keys{$b . ''} = 1;
    $valid_keys{sprintf('%02d', $i) . ''} = 1;
}

# ASSERT
die unless(scalar keys %valid_keys == 100);

# Create a list of a list with valid section numbers, including sub keys
#   Example element: ['18', '1', '8']
my @valid_subkeys = map {
    length $_ == 1 ? [$_] : [$_, split('', $_)]
} sort {$a cmp $b} keys %valid_keys;



# Actually run now
if($ARGV[0] and looks_like_number($ARGV[0])) {
    find_valid_keys($ARGV[0]);
}
else {
    find_valid_keys($_) for (1..10);
}




=head1 INTERNAL METHODS

=over

=item find_valid_keys

Runs through the list of possible section keys and recursively builds a key up
to the given length. At the end it prints out the number of valid and total
keys.

=cut


sub find_valid_keys {
    my $max = shift;

    print "Finding valid keys for length $max\n";

    my $total_valid_keys = 0;

    # Recursive testing of all keys
    foreach my $k0 (@valid_subkeys) {
        my @key = ($k0->[0]);
        $total_valid_keys += subkey_count($max, @key);
    }

    print "Valid keys\t: $total_valid_keys\n";

    my $total_possible = 1;
    for(my $i = 0; $i < $max; $i++ ) {
        $total_possible *= 100 - $i;
    }

    print "Total keys\t: $total_possible\n";
    print "Result\t\t: " . ($total_valid_keys / $total_possible * 100) . "% valid keys\n\n";

}

=item subkey_count

Recursively joins keys together up to the max length and returns 1 if
successful. Makes sure that no key is present twice, not even their subkeys.

Example: if 18 is already part of the key then 1, 8 or 18 can't be used again.

=cut

sub subkey_count {
    my $max = shift;
    my @key = @_;

    my $key_length = scalar @key;

    # Given maximum length reached... we're done
    if($key_length == $max) {
        return 1;
    }

    my $key_count = 0;

    my @test_key = map { split('', $_) } @key;

    TESTKEY: foreach my $subkeys (@valid_subkeys) {
        foreach my $subkey (@$subkeys) {
            my $matches = grep { $_ eq $subkey } @test_key;
            next TESTKEY if($matches);
        }

        $key_count += subkey_count($max, @key, $subkeys->[0]);
    }

    return $key_count;
}

=back

=head1 AUTHOR

Moritz Dulies

=head1 COPYRIGHT

Public domain

=cut