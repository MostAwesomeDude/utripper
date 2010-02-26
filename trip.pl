#! /usr/bin/perl -w

my $precision = 10;

sub trip($) {
  my $seed = shift;
  my $salt = substr($seed, 1, 2);

  $salt =~ tr/\x3A-\x40\x5B-\x60/A-Ga-f/;
  $salt =~ s/[^\.\/0-9A-Za-z]/./g;

  return(substr(crypt($seed, $salt), -$precision));
}

print trip($ARGV[0]), "\n";
