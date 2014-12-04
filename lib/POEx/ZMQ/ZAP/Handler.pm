package POEx::ZMQ::ZAP::Handler;

use strictures 1;

use POE;
use POEx::ZMQ;

use Types::Standard   -types;
use POEx::ZMQ::Types  -types;

use constant ZAP_VERSION => '1.0';

use Moo; use MooX::late;
with
  'MooX::Role::POE::Emitter',

  'POEx::ZMQ::ZAP::Role::Whitelisting',
  'POEx::ZMQ::ZAP::Role::Blacklisting',
  'POEx::ZMQ::ZAP::Role::PlainHandler',
  'POEx::ZMQ::ZAP::Role::ZCertHandler',
;

has context => (
  required  => 1,
  is        => 'ro',
  isa       => ZMQContext,
);

has _zsock => (
  lazy      => 1,
  is        => 'ro',
  isa       => ZMQSocket[ZMQ_ROUTER],
  clearer   => '_clear_zsock',
  builder   => sub {
    POEx::ZMQ->socket(
      context => $self->context,
      type    => ZMQ_ROUTER,
    )
  },
);


has logger => (
  lazy      => 1,
  is        => 'ro',
  isa       => CodeRef,
  builder   => sub {
    sub { my $level = shift; warn "$level -> ", @_, "\n" } 
  },
);


sub BUILD {
  # FIXME emitter object_states cfg
  $self->set_event_prefix('zap_') unless $self->has_event_prefix;
  $self->_start_emitter
}

sub stop {
  $self->_zsock->stop;
  $self->_clear_zsock;
  $self->_shutdown_emitter
}


sub _start {
  my ($kernel, $self) = @_[KERNEL, OBJECT];

  $self->_zsock->bind('inproc://zeromq.zap.01');
}

sub zmq_recv_multipart {
  my ($self, $parts) = @_;
  my $envelope = $parts->items_before(sub { ! length });
  my $body     = $parts->items_after(sub { ! length });

  if ($body->count < 6) {
    $self->logger->(info => "Not enough frames in ZAP request");
    if ( $body->exists(1) ) {
      $self->_send_error_reply(
        $envelope, $body->get(1), 400 => 'Not enough frames'
      )
    } else {
      $self->logger->(info => "Cannot reply to malformed ZAP request")
    }
    return
  }

  my (
    $version,         # version frame (three bytes; '1.0' expected)
    $req_id,          # binary blob [optional]
    $domain,          # string
    $address,
    $identity,
    $mechanism,       # string; NULL, PLAIN, CURVE
    @credentials      # zero or more binary blobs
  ) = $body->all;

  $domain = '-all' unless defined $domain and length $domain;

  unless ($version eq ZMQ_VERSION) {
    $self->_send_error_reply(
      $envelope, $req_id, 400 => 'Invalid version'
    );
    return
  }

  # FIXME check address against explicit whitelist / blacklist
  
  AUTH: {
    if ($mechanism eq 'NULL') {
      # FIXME allowed
    }

    if ($mechanism eq 'PLAIN') {
      # FIXME get result obj from PlainHandler
    }

    if ($mechanism eq 'CURVE') {
      # FIXME get result obj from CurveHandler
    }

    # FIXME unknown mechanism
  } # AUTH

  # FIXME send appropriate 200/400
}

sub _send_error_reply {
  my ($self, $envelope, $req_id, $code, $txt) = @_;

  my $zmsg = $self->_assemble_reply_msg(
    request_id  => $req_id, 
    status_code => $code, 
    status_text => $txt,
  );

  $self->_zsock->send_multipart(
    [ $envelope, '', $zmsg ]
  );
}

sub _send_auth_reply {
  # FIXME
}

sub _assemble_reply_msg {
  my ($self, %params) = @_;

  for my $required (qw/request_id status_code status_text/) {
    confess "Missing required parameter '$required'"
      unless defined $params{$required}
  }

  $params{user_id}  //= '';
  $params{metadata} //= '';

  (
    ZMQ_VERSION,
    $params{request_id},
    $params{status_code},
    $params{status_text},
    $params{user_id},
    $params{metadata}
  )
}

#  
# low-pri
#  - proxy mode; handler may connect or bind tcp:// endpoint
#    for connecting/accepting external handlers ?
#    https://github.com/zeromq/rfc/blob/master/src/spec_27.c#L100
#
# notes
#  see pyzmq wrt whitelisting, blacklisting
#  Crypt::ZCert for cert dirs
#  investigate CURVE auth details (zmq rfc)
#  whitelist files?

1;

# vim: ts=2 sw=2 et sts=2 ft=perl
