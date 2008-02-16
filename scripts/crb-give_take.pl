#!/usr/bin/perl -w
#
# crb-give_take.pl
# WHAT:  Wider functionality on give and take in WZDFTPD! it now works like gl.
# USAGE: - put inside the directory of your choosing, i have /opt/wzdftpd/bin
#        - add in wzd.cnf:
#          [custom_commands]
#          site_take = perl:/path/to/crb-give_take.pl take
#          site_give = perl:/path/to/crb-give_take.pl give
###

sub give {
  my $credits = wzd::vars_user get, $user, credits;
  $new_credits = $credits + $_[0];
  wzd::vars_user set, $user, credits, "$new_credits";
}

sub take {
  my $credits = wzd::vars_user get, $user, credits;
  $new_credits = $credits - $_[0];
#  wzd::send_message("200 Here: $credits - $_[0] = $new_credits");
  if ($new_credits >= 0 ) {
    wzd::vars_user set, $user, credits, "$new_credits";
  } else {
    wzd::send_message("200 Malformed request, user has insufficient credits.");
    die;
  }
}

sub errmsg {
  wzd::send_message("200 Malformed request, Usage: SITE $_[0] <user> <credits>");
  wzd::send_message("200 credits can be suffixed with K(kilo), M(mega) or G(giga)");
}

($action, $user, $amount) = split ' ', $wzd::args;

# sanity checks
my $uc_action = uc($action);
@wzd_args = split(/\s/, $wzd::args);
my $num_args = scalar(@wzd_args);

if ($num_args != 3) {
  errmsg( $uc_action );
  die;
} 

if (!($amount =~ /\A\d+[KMG]{0,1}\z/)) {
  errmsg( $uc_action );
  die;
}

if ($amount =~ /\A\d+\z/) {
  $byte_amount = $amount;
  $amount = $amount . "b";
}
elsif ($amount =~ /\A\d+K\z/) {
  $byte_amount = $amount * 1024;
}
elsif ($amount =~ /\A\d+M\z/) {
  $byte_amount = $amount * 1048576;
}
elsif ($amount =~ /\A\d+G\z/) {
  $byte_amount = $amount * 1073741824;
}

if ($action eq "give") {
  give( $byte_amount );
  wzd::send_message("200 Gave $amount to $user");
}
elsif ($action eq "take") {
  take( $byte_amount );
  wzd::send_message("200 Took $amount from $user");
}

