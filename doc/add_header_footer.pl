#!/usr/bin/perl

my $filename_head="../html_head.html";
my $filename_tail="../html_tail.html";

while (<>) {
  if ( /(.*)<BODY/) {
    print "$1\n";
    while (<>) {
      if ( />(.*)/ )
      {
        system("cat $filename_head");
        print "<div ID=\"content\">$1\n";
        last;
      }
    }
  } elsif ( /(.*)<\/BODY/) {
    print "$1\n";
    while (<>) {
      if ( />(.*)/ )
      {
        print "</div>\n";
        system("cat $filename_tail");
        print "</body>$1\n";
        last;
      }
    }
  } else {
    print;
  }
}
