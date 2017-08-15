# NAME

valid\_keys\_dt67502.pl - counts the number of valid keys for encryption algorithm
DT 67502

# SYNOPSIS

    ./valid_keys_dt67502.pl

    ./valid_keys_dt67502.pl 4

# DESCRIPTION

Counts (by brute force) the number of valid keys for the DT 67502 algorithm
as used in the GDR. It also counts the number of invalid keys and compares
which percentage is valid.

This script only runs for a small number of columns but proves that there is
a relatively low number of actual valid keys.

Tests column widths from 1 to 10, although you're unlikely to get a result for
5 or higher. No attempt was made to make this performant.

# COPYRIGHT

Public domain
