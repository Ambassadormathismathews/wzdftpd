package wzdftpd;

use 5.008004;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use wzdftpd ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
  wzd_fini
  wzd_init
  wzd_send_message
	
);

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('wzdftpd', $VERSION);

# Preloaded methods go here.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

wzdftpd - Perl extension for libwzd (wzdftpd)

=head1 SYNOPSIS

  use wzdftpd;

  wzd_init("localhost",21,"wzdftpd","wzdftpd") or die "unable to connect";

  my @reply = wzd_send_message("site who");
  foreach my $line (@reply) {
    print "$line\n";
  }

  wzd_fini();

=head1 DESCRIPTION

The wzdftpd allows you to control/send commands to a wzdftpd server.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

=head2 RFC

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

=head2 URLs

Homepage: http://www.wzdftpd.net

=head1 AUTHOR

Pierre Chifflier, E<lt>pollux@cpe.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Pierre Chifflier

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
