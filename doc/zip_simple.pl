##for wzdftpd community
##simple .zip checker
##
##
##Put in wzd.cfg under 'cscript'
##cscript = POSTUPLOAD perl:c:/wzdftpd/scripts/zip_check.pl %username %usergroup {%filepath}
##
##
##set path to unzip.exe
my %binary;
$binary{UNZIP} = "./scripts/unzip.exe";
##
##
##main proc
sub zip_check {

  my ($user,$group,$file) = split " ", $wzd_args, 3;
  if ($file =~ m/.*\.zip/i) {
    my @args = ($binary{UNZIP}, "-qqt", "$file");
    my $rc = system( @args );
    if ($rc == 0) {
      wzd::send_message "+----------------------------------------------------";
      wzd::send_message "$user\($group\) uploaded GOOD zip file '$file'.";
      wzd::send_message "+----------------------------------------------------";
    } else {
      rename "$file", "$file.bad";
      wzd::send_message "+----------------------------------------------------";
      wzd::send_message "$user\($group\) uploaded BAD zip file '$file'.";
      wzd::send_message "+----------------------------------------------------";
    }
  }
}

zip_check;

