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

=pod

=head1 NAME

POEx::ZMQ::ZAP::Role::AddressHandler - Add an AddressList to a ZAP handler

=head1 SYNOPSIS

FIXME

=head1 DESCRIPTION

FIXME link to AddressList and Masks details

=head2 ATTRIBUTES

=head3 address_auth_via

Required; a string describing the type of address authentication in use,
either C<blacklist> or C<whitelist>.

Defaults to C<blacklist>.

=head3 addresslist

The actual L<POEx::ZMQ::ZAP::AddressList> instance; see the
L<POEx::ZMQ::ZAP::AddressList> documentation for details.

=head2 METHODS

=head3 deny_mask

FIXME link to Masks doc in AddressList

=head3 allow_mask

FIXME

=head3 addr_is_whitelisted

FIXME

=head3 addr_is_blacklisted

FIXME

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
