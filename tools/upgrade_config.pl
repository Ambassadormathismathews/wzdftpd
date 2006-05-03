#!/usr/bin/perl -w
#
# upgrade_config.pl: upgrade wzdftpd config file to the latest version
#    Takes the filename as first argument, and will create a file $filename-NEW
#
# apt-get install libconfig-inifiles-perl
#
# WARNING !!!
#
# the .ini file format does not allow empty lines, and of course the default config of wzdftpd
# contains many of them. Upgrading the config WILL DELETE empty lines, which has no effect
# on configuration (only a cosmetic change).
# 
# This script is rather untested

use strict;
use Config::IniFiles;

my $debug = 0; # set to 1 to get verbose output



my $latest_version = "0.8.0";
my %transition_state = (
        "0.8.0" => [\&up_to_date, $latest_version],
        "0.7.1" => [\&update_071, "0.8.0"],
        "0.7.0" => [\&update_nothing,"0.7.1"],
        undef => [\&update_impossible,undef]
);
my $upgrade_function;
my $current_version;
my $old_version;
my $temp_version;


#### main code

my $config_file = shift or die "usage: $0 configfile";

my $cfg = new Config::IniFiles( -file => "$config_file" ) or die "Could not open $config_file";

update_impossible() unless $cfg->val( 'GLOBAL', 'config version' );
$current_version = $cfg->val( 'GLOBAL', 'config version' );
$old_version = $current_version;


# main upgrade loop
while ($current_version ne $latest_version) {
  $upgrade_function = $transition_state{$current_version}[0];
  $temp_version = &{$upgrade_function}($current_version);
  $temp_version or die "Error while upgrading from $current_version to $transition_state{$current_version}[1]\n";
  print "Upgrade successful from $current_version to $temp_version\n" if $debug;
  $current_version = $temp_version;
}

print "Upgrade successful from $old_version to $latest_version\n";

$cfg->WriteConfig ("$config_file-NEW");







##### procedures


sub update_impossible
{
  print "Unable to upgrade your configuration\n";
  print "Upgrade is possible for versions >= 0.7.0\n";
  print "Please also check that 'config version = 0.x.y' is present in your config\n";
  exit 1;
}

sub update_nothing
{
  my ($old_version) = @_;
  print "Nothing to do for $old_version\n" if $debug;
  update_version($old_version,$transition_state{$old_version}[1]);
  return $transition_state{$old_version}[1];
}

sub update_version
{
  my ($from,$to) = @_;

  $cfg->setval( 'GLOBAL', 'config version', $to);
}

sub move_parameter
{
  my ($section,$param,$newsection,$newparam) = @_;

  if ($section ne $newsection) {
    $cfg->AddSection ( $newsection ) unless $cfg->SectionExists ( $newsection );
  }
  if ($cfg->val( $newsection, $newparam )) {
    $cfg->setval($newsection, $newparam, $cfg->val( $section, $param ));
  } else {
    $cfg->newval($newsection, $newparam, $cfg->val( $section, $param ));
  }
  $cfg->delval($section,$param);
}

sub update_071
{
  my ($old_version) = @_;

  print "Upgrading zeroconf parameters\n" if $debug;
  # check if we have zeroconf_name or zeroconf_test
  move_parameter('GLOBAL','zeroconf_name','ZEROCONF','zeroconf_name');
  move_parameter('GLOBAL','zeroconf_port','ZEROCONF','zeroconf_port');

  update_version($old_version,$transition_state{$old_version}[1]);
  return $transition_state{$old_version}[1];
}
