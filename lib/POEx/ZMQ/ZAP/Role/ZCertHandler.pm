package POEx::ZMQ::ZAP::Role::ZCertHandler;

use strictures 1;

use Carp;
use Path::Tiny;

use Types::Standard       -types;
use Types::Path::Tiny     -types;
use List::Objects::Types  -types;

use Crypt::ZCert;
use POEx::ZMQ::ZAP::ZCerts;


use Moo::Role; use MooX::late;

has zcerts => (
  lazy      => 1,
  is        => 'ro',
  isa       => InstanceOf['POEx::ZMQ::ZAP::ZCerts'],
  builder   => sub { POEx::ZMQ::ZAP::ZCerts->new },
);

# FIXME handle all CURVE auth bits here?

1;
