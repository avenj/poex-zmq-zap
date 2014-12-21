package POEx::ZMQ::ZAP::Role::PlainHandler;

use strictures 1;
use Carp;

use List::Objects::WithUtils;

use Types::Standard   -types;

use POEx::ZMQ::ZAP::PlainAuth;
use POEx::ZMQ::ZAP::Result;


use Moo::Role; use MooX::late;


has plain => (
  lazy      => 1,
  is        => 'ro',
  isa       => InstanceOf['POEx::ZMQ::ZAP::PlainAuth'],
  builder   => sub { POEx::ZMQ::ZAP::PlainAuth->new },
  handles   => +{
    plain_setup_user => 'setup_user',
    plain_check      => 'check',
  },
);

sub plain_authenticate {
  my ($self, $domain, $username, $pwd) = @_;
  $domain //= '';

  my ($reason, $allowed) = '';

  if (!defined $username || !defined $pwd) {
    $reason = "Invalid credentials"
  } elsif ( !$self->plain_check($domain, $username, $pwd) ) {
    $reason = "Authentication failed"
  } else {
    $allowed = 1
  }

  POEx::ZMQ::ZAP::Result->new(
    domain   => $domain,
    username => $username,
    allowed  => $allowed,
    reason   => $reason,
  )
}

1;

=pod

=cut
