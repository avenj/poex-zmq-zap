package POEx::ZMQ::ZAP::Role::CurveHandler;

use strictures 1;

use Carp;

use Types::Standard       -types;
use Types::Path::Tiny     -types;
use List::Objects::Types  -types;

use Path::Tiny;
use Crypt::ZCert;

use POEx::ZMQ::ZAP::CurveAuth;
use POEx::ZMQ::ZAP::Internal::Result;


use Moo::Role; use MooX::late;

has curve => (
  lazy      => 1,
  is        => 'ro',
  isa       => InstanceOf['POEx::ZMQ::ZAP::CurveAuth'],
  builder   => sub { POEx::ZMQ::ZAP::CurveAuth->new },
  handles   => +{
    curve_setup_certificate => 'setup_certificate',
    curve_setup_key         => 'setup_key',
    curve_check             => 'check',
  },
);

sub curve_authenticate {
  my ($self, $domain, $pubkey) = @_;
  $domain //= '';

  my ($reason, $allowed) = '';

  if (!defined $pubkey) {
    $reason = "Invalid credentials"
  } elsif ( !$self->curve_check($domain, $pubkey) ) {
    $reason = "Authentication failed"
  } else {
    $allowed = 1
  }

  POEx::ZMQ::ZAP::Internal::Result->new(
    domain  => $domain,
    allowed => $allowed,
    reason  => $reason,
  )
}

1;
