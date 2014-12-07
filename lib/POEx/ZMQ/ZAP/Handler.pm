package POEx::ZMQ::ZAP::Handler;

use strictures 1;

use POE;
use POEx::ZMQ;

use Types::Standard   -types;
use POEx::ZMQ::Types  -types;

use POEx::ZMQ::ZAP::Internal::Request;
use POEx::ZMQ::ZAP::Internal::Reply;


use Moo; use MooX::late;
with 'MooX::Role::POE::Emitter';

use constant ZAP_VERSION => '1.0';

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


with
  'POEx::ZMQ::ZAP::Role::AddressHandler',
  'POEx::ZMQ::ZAP::Role::PlainHandler',
  'POEx::ZMQ::ZAP::Role::ZCertHandler',
;


sub BUILD {
  my ($self) = @_;
  $self->set_object_states(
    [
      $self => +{
        emitter_started => '_emitter_started',
        emitter_stopped => '_emitter_stopped',
        zmq_recv_multipart => 'zmq_recv_multipart',
      },
    ]
  );
  $self->set_alias('ZAP') unless $self->has_alias;
  $self->set_event_prefix('zap_') unless $self->has_event_prefix;
  $self->_start_emitter
}

sub stop {
  $self->_zsock->stop;
  $self->_clear_zsock;
  $self->_shutdown_emitter
}


sub _emitter_started {
  my ($kernel, $self) = @_[KERNEL, OBJECT];

  $self->_zsock->bind('inproc://zeromq.zap.01');
}

sub _emitter_stopped {

}

sub zmq_recv_multipart {
  my ($self, $parts) = @_;
  my $envelope = $parts->items_before(sub { ! length });
  my $body     = $parts->items_after(sub { ! length });

  return unless $self->_verify_zap_args($body); 

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

  my $zrequest = POEx::ZMQ::ZAP::Internal::Request->new(
    envelope    => $envelope,
    request_id  => $req_id,
    domain      => $domain,
    address     => $address,
    identity    => $identity,
    mechanism   => $mechanism,
    credentials => array(@credentials),
  );

  $self->_dispatch_zap_auth($zrequest)
}

sub _verify_zap_args {
  my ($self, $body) = @_;

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

  1
}

sub _dispatch_zap_auth {
  my ($self, $zrequest) = @_;

  my $result;
  # FIXME check ->address against explicit whitelist / blacklist
  
  AUTH: {
    if ($mechanism eq 'NULL') {
      $result = hash(
        domain  => $zrequest->domain,
        allowed => 1,
        reason  => '',
      )->inflate;
      last AUTH
    }

    if ($mechanism eq 'PLAIN') {
      my ($user, $passwd) = $zrequest->credentials->all;
      # FIXME check for missing user/passwd
      $result = $self->plain_authenticate(
        $zrequest->domain => $user => $passwd
      );
      last AUTH
    }

    if ($mechanism eq 'CURVE') {
      # FIXME get pubkey from creds and ->curve_authenticate
      last AUTH
    }

    # FIXME unknown mechanism
  } # AUTH

  # FIXME send appropriate 200/400
  if ($result->allowed) {

  } else {

  }
}

sub _send_error_reply {
  my ($self, $envelope, $req_id, $code, $txt) = @_;

  my @reply = $self->_assemble_reply_msg(
    request_id  => $req_id, 
    status_code => $code, 
    status_text => $txt,
  );

  $self->_zsock->send_multipart(
    [ $envelope, '', @reply ]
  );
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

#  TODO
#  - proxy mode; handler may connect or bind tcp:// endpoint
#    for connecting/accepting external handlers ?
#    https://github.com/zeromq/rfc/blob/master/src/spec_27.c#L100

1;

# vim: ts=2 sw=2 et sts=2 ft=perl
