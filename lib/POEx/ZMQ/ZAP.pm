package POEx::ZMQ::ZAP;

use strictures 1;
use Carp;
use Scalar::Util 'blessed';

use Moo::Role ();


use Exporter::Tiny;
our @EXPORT = our @EXPORT_OK = qw/
  add_zap_options
  create_zap_handler
/;


sub add_zap_options {
  my ($zsock) = @_;
  confess "Expected a POEx::ZMQ::Socket but got $zsock"
    unless blessed $zsock and $zsock->isa('POEx::ZMQ::Socket');
  Moo::Role->apply_roles_to_object( $zsock,
    'POEx::ZMQ::ZAP::Role::SocketOptions'
  );
  $zsock
}

sub create_zap_handler {
  # FIXME
}


print
  qq[<Capn_Refsmmat> rofer: who needs ethics committees? ],
   qq[I ran everything by avenj\n],
  qq[<rofer> I think avenj and ethics committees probably ],
   qq[have mutually exclusive opinions\n]
unless caller; 1;
