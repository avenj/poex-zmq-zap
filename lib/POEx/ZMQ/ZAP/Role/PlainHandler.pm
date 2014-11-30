package POEx::ZMQ::ZAP::Role::PlainHandler;

use strictures 1;
use Carp;



use Moo::Role; use MooX::late;

has plain => (
  lazy      => 1,
  is        => 'ro',
  isa       => InstanceOf['POEx::ZMQ::ZAP::PlainAuth'],
  builder   => sub { POEx::ZMQ::ZAP::PlainAuth->new },
  handles   => +{
    # FIXME
  },
);

sub plain_authenticate {
  # FIXME
}

1;
