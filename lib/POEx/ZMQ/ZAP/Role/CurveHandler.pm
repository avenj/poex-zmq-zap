package POEx::ZMQ::ZAP::Role::CurveHandler;

use strictures 1;

use Carp;
use Path::Tiny;

use Types::Standard       -types;
use Types::Path::Tiny     -types;
use List::Objects::Types  -types;

use Crypt::ZCert;
use POEx::ZMQ::ZAP::ZCerts;


use Moo::Role; use MooX::late;

has curve => (
  lazy      => 1,
  is        => 'ro',
  isa       => InstanceOf['POEx::ZMQ::ZAP::ZCerts'],
  builder   => sub { POEx::ZMQ::ZAP::ZCerts->new },
  handles   => +{
    curve_setup_certificate => 'setup_certificate',
    curve_setup_key         => 'setup_key',
    curve_check             => 'check',
  },
);

1;
