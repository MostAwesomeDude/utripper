#! /usr/bin/perl -w

# cat old.log | perl 8to10.pl

sub trip10($) {
  my $seed = shift;
  my $salt = substr($seed, 1, 2);
  $salt =~ tr/\x3A-\x40\x5B-\x60/A-Ga-f/;
  $salt =~ s/[^\.\/0-9A-Za-z]/./g;
  return(substr(crypt($seed, $salt), -10));
}

while (<>) {
    if ($_ =~ /^(........) : #(........)/) {
	my $x;
	$x = trip10($2);
	print "$x : #$2\n";
    }
}
