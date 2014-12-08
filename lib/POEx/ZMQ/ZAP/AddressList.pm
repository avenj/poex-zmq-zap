package POEx::ZMQ::ZAP::AddressList;

use Carp;
use strictures 1;

use List::Objects::Types  -types;
use Types::Standard       -types;


sub _match {
  my ($mask, $addr) = @_;
  $addr = uc $addr;

  my $quoted = quotemeta uc $mask;
  $quoted =~ s/\\\*/[\x01-\xFF]{0,}/g;
  $quoted =~ s/\\\?/[\x01-\xFF]{1,1}/g;

  $addr =~ /^$quoted$/
}


use Moo; use MooX::late;

has masks => (
  lazy      => 1,
  is        => 'ro',
  isa       => TypedArray[ (Str | RegexpRef) ],
  coerce    => 1,
  builder   => sub { [] },
  handles   => +{
    add_mask   => 'push',
    list_masks => 'all',
  },
);

sub has_match {
  my ($self, $addr) = @_;
  confess "Expected an address" unless defined $addr and length $addr;
  $self->masks->has_any(sub { 
    ref eq 'Regexp' ? $addr =~ $_ : _match($_, $addr)
  })
}

sub del_mask {
  my ($self, $mask) = @_;

  $self->masks->delete_when(sub {
    if (ref) {
      return unless ref $mask
    } else {
      return if ref $mask
    }
    $mask eq $_
  });
}

1;

=pod

=head1 NAME

POEx::ZMQ::ZAP::AddressList - IP address whitelist/blacklist for POEx::ZMQ::ZAP

=head1 SYNOPSIS

FIXME

=head1 DESCRIPTION

FIXME

=head2 Masks

FIXME

=head2 ATTRIBUTES

=head3 masks

A L<List::Objects::WithUtils::Array::Typed> containing either strings
(glob-like masks) or C<Regexp>-type objects addresses will be matched against.

=head2 METHODS

=head3 has_match

Takes an IP address; returns true if the address matches an entry present on
the list.

=head3 add_mask

Adds IP addresses, masks, or regular expressions to the list for future
matching via L</has_match>.

Takes either a complete address, a glob-like mask (see L</Masks>), or a
C<Regexp>-type object (typically produced via the C<qr//> operator).

=head3 list_masks

Returns the complete list of L</masks>; this is the same as calling 
C<< $addrlist->masks->all >>.

=head3 del_mask

Removes IP addresses, masks, or regular expressions from the L</masks> list.

Takes either a complete address, a glob-like mask (see L</Masks>), or a
C<Regexp>-type object (typically produced via the C<qr//> operator).

(If a C<Regexp>-type object is provided, stringy comparison is used; in other
words, the exact object present on the list need not be used.)

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
