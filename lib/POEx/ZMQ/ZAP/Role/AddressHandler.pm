package POEx::ZMQ::ZAP::Role::AddressHandler;

use Carp;
use strictures 1;

use Types::Standard   -types;


use POEx::ZMQ::ZAP::AddressList;


use Moo::Role; use MooX::late;


has address_auth_via => (
  lazy      => 1,
  is        => 'ro',
  isa       => Maybe[ Enum[qw/whitelist blacklist/] ],
  builder   => sub { undef },
);


has _addrlist => (
  lazy      => 1,
  is        => 'ro',
  isa       => InstanceOf['POEx::ZMQ::ZAP::AddressList'],
  builder   => sub { POEx::ZMQ::ZAP::AddressList->new },
);


sub addr_is_whitelisted {
  my ($self, $addr) = @_;
  return unless $self->address_auth_via eq 'whitelist';
  $self->_addrlist->has_match($addr)
}

sub addr_is_blacklisted {
  my ($self, $addr) = @_;
  return unless $self->address_auth_via eq 'blacklist';
  $self->_addrlist->has_match($addr)
}

1;
