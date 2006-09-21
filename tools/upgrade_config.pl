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

# Set non non-zero to get verbose output
# 1: script general actions, version transitions
# 2: modifications on keys
my $debug = 0;



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
    print "Adding section $newsection\n" if ($debug > 1);
    $cfg->AddSection ( $newsection ) unless $cfg->SectionExists ( $newsection );
  }
  if ($cfg->val( $newsection, $newparam )) {
    print "Replacing value [$newsection]:$newparam = ". $cfg->val( $section, $param ) . "\n" if ($debug > 1);
    $cfg->setval($newsection, $newparam, $cfg->val( $section, $param ));
  } else {
    print "Adding value [$newsection]:$newparam = ". $cfg->val( $section, $param ) . "\n" if ($debug > 1);
    $cfg->newval($newsection, $newparam, $cfg->val( $section, $param ));
  }
  print "Deleting [$section]:$param\n" if ($debug > 1);
  $cfg->delval($section,$param);
}

sub update_071
{
  my ($old_version) = @_;
  my $value;

  print "Upgrading zeroconf parameters\n" if $debug;
  # check if we have zeroconf_name or zeroconf_test
  move_parameter('GLOBAL','zeroconf_name','ZEROCONF','zeroconf_name');
  move_parameter('GLOBAL','zeroconf_port','ZEROCONF','zeroconf_port');

  print "Upgrading sfv parameters\n" if $debug;
  move_parameter('GLOBAL','param_sfv_progressmeter','sfv','progressmeter');
  move_parameter('GLOBAL','param_sfv_del_progressmeter','sfv','del_progressmeter');
  move_parameter('GLOBAL','param_sfv_incomplete_indicator','sfv','incomplete_indicator');
  move_parameter('GLOBAL','param_sfv_other_completebar','sfv','other_completebar');
  if ( ($value=$cfg->val('sfv','incomplete_indicator')) ) {
    $value =~ s/%0/%releasename/;
    $cfg->setval('sfv', 'incomplete_indicator', $value);
  }

  update_version($old_version,$transition_state{$old_version}[1]);
  return $transition_state{$old_version}[1];
}
