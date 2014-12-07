package POEx::ZMQ::ZAP::AddressList;

use Carp;
use strictures 1;

use List::Objects::Types  -types;
use Types::Standard       -types;


sub _match {
  my ($mask, $addr) = @_;
  $addr = lc $addr;

  my $quoted = quotemeta lc $mask;
  $quoted =~ s/\\\*/[\x01-\xFF]{0,}/g;
  $quoted =~ s/\\\?/[\x01-\xFF]{1,1}/g;

  $addr =~ /^$quoted$/
}


use Moo; use MooX::late;

has masks => (
  lazy      => 1,
  is        => 'ro',
  isa       => ArrayObj,
  coerce    => 1,
  builder   => sub { [] },
  handles   => +{
    list_masks => 'all',
  },
);

sub matches {
  my ($self, $addr) = @_;
  confess "Expected an address" unless defined $addr;
  $self->masks->has_any(sub { 
    ref $_ eq 'Regexp' ? $addr =~ $_ : _match($_, $addr)
  })
}

sub add_mask {
  my ($self, $mask) = @_;
  confess 'Expected an address mask or a qr// Regexp object'
    unless defined $mask and ref $mask eq 'Regexp' or not ref $mask;
  $self->masks->push($mask);
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
