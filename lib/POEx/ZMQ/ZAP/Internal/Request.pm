package POEx::ZMQ::ZAP::Internal::Request;

use strictures 1;


use Types::Standard       -types;
use List::Objects::Types  -types;


use Moo; use MooX::late;

has envelope => (
  required  => 1,
  is        => 'ro',
  isa       => ArrayObj,
  coerce    => 1,
);

has request_id => (
  required  => 1,
  is        => 'ro',
  isa       => Defined,
);

has domain => (
  lazy      => 1,
  is        => 'ro',
  isa       => Str,
  builder   => sub { '' },
);

has address => (
  required  => 1,
  is        => 'ro',
  isa       => Str,
);

has identity => (
  lazy      => 1,
  is        => 'ro',
  builder   => sub { '' },
);

has mechanism => (
  required  => 1,
  is        => 'ro',
  isa       => Str,
);

has credentials => (
  lazy      => 1,
  is        => 'ro',
  isa       => ArrayObj,
  coerce    => 1,
  builder   => sub { [] }
);


1;
