package POEx::ZMQ::ZAP::Role::AddressHandler;

use Carp;
use strictures 1;

use Types::Standard   -types;


use POEx::ZMQ::ZAP::AddressList;


use Moo::Role; use MooX::late;


has address_auth_via => (
  lazy      => 1,
  is        => 'ro',
  isa       => Enum[qw/whitelist blacklist/],
  builder   => sub { 'blacklist' },
);


has accesslist => (
  lazy      => 1,
  is        => 'ro',
  isa       => InstanceOf['POEx::ZMQ::ZAP::AddressList'],
  builder   => sub { POEx::ZMQ::ZAP::AddressList->new },
);


sub deny_mask {
  my $self = shift;
  confess "deny_mask cannot be used when address_auth_via => 'whitelist'"
    if $self->address_auth_via eq 'whitelist';
  $self->accesslist->add_mask(@_)
}

sub allow_mask {
  my $self = shift;
  confess "allow_mask cannot be used when address_auth_via => 'blacklist'"
    if $self->address_auth_via eq 'blacklist';
  $self->accesslist->add_mask(@_)
}


sub addr_is_whitelisted {
  my ($self, $addr) = @_;
  return unless $self->address_auth_via eq 'whitelist';
  $self->accesslist->has_match($addr)
}

sub addr_is_blacklisted {
  my ($self, $addr) = @_;
  return unless $self->address_auth_via eq 'blacklist';
  $self->accesslist->has_match($addr)
}

1;
