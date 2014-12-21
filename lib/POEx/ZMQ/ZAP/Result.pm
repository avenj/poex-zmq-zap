package POEx::ZMQ::ZAP::Result;

use strictures 1;

use Types::Standard   -types;


use Moo; use MooX::late;

has allowed => (
  required  => 1,
  is        => 'ro',
  isa       => Bool,
);

has domain => (
  required  => 1,
  is        => 'ro',
  isa       => Str,
);

has reason  => (
  lazy      => 1,
  is        => 'ro',
  isa       => Str,
  builder   => sub { '' },
);


has username => (
  lazy      => 1,
  is        => 'ro',
  isa       => Str,
  predicate => 'has_username',
  builder   => sub { '' },
);

1;
