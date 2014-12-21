package POEx::ZMQ::ZAP::Handler;

use strictures 1;

use POE;
use POEx::ZMQ;

use Types::Standard   -types;
use POEx::ZMQ::Types  -types;

use POEx::ZMQ::ZAP::Request;
use POEx::ZMQ::ZAP::Result;


use Moo; use MooX::late;

with
  'MooX::Role::POE::Emitter',
  'POEx::ZMQ::ZAP::Role::AddressHandler',
  'POEx::ZMQ::ZAP::Role::PlainHandler',
  'POEx::ZMQ::ZAP::Role::ZCertHandler',
;

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
    my ($self) = @_;
    POEx::ZMQ->socket(
      context => $self->context,
      type    => ZMQ_ROUTER,
    )
  },
);


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
  my ($self) = @_;
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

  my $zap_args = $self->_verify_zap_args($envelope, $body);
  return unless $zap_args;

  my (
    $version, $req_id, $domain, $address, $identity, $mechanism, @credentials
  ) = @$zap_args;

  my $zrequest = POEx::ZMQ::ZAP::Request->new(
    envelope    => $envelope,
    request_id  => $req_id,
    domain      => $domain,
    address     => $address,
    identity    => $identity,
    mechanism   => $mechanism,
    credentials => array(@credentials),
  );

  # FIXME optional Object::RateLimiter-based rate limiting
  #   on address or address+envelope ?

  $self->_dispatch_zap_auth($zrequest)
}

sub _verify_zap_args {
  my ($self, $envelope, $body) = @_;

  if ($body->count < 6) {
    if ( $body->exists(1) ) {
      $self->_send_error_reply(
        $envelope, $body->get(1), 400 => 'Not enough frames'
      )
    } else {
      $self->emit( log => fail => "Cannot reply to malformed ZAP request" )
    }
    $self->emit( log => fail => "Not enough frames in ZAP request" );
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

  unless ($version eq ZAP_VERSION) {
    $self->_send_error_reply(
      $envelope, $req_id, 400 => 'Invalid version'
    );
    $self->emit( log => fail => "Invalid version in ZAP request [$address]" );
    return
  }

  $address = '' unless defined $address and length $address;
  $domain  = '' unless defined $domain  and length $domain;

  [
    $version, $req_id, $domain, $address, $identity, $mechanism, @credentials
  ]
}

sub _dispatch_zap_auth {
  my ($self, $zrequest) = @_;
  my $mechanism = $zrequest->mechanism;
  my $result;

  AUTH: {
    if ($self->address_auth_via eq 'whitelist') {
      unless ( $self->addr_is_whitelisted($zrequest->address) ) {
        $result = POEx::ZMQ::ZAP::Result->new(
          allowed => 0,
          reason  => 'Address not in whitelist',
          domain  => $zrequest->domain,
        );
        last AUTH
      }
    } elsif ($self->address_auth_via eq 'blacklist') {
      if ( $self->addr_is_blacklisted($zrequest->address) ) {
        $result = POEx::ZMQ::ZAP::Result->new(
          allowed => 0,
          reason  => 'Address is blacklisted',
          domain  => $zrequest->domain,
        );
        last AUTH
      }
    }
   
    if ($mechanism eq 'NULL') {
      $result = POEx::ZMQ::ZAP::Result->new(
        allowed => 1,
        reason  => '',
        domain  => $zrequest->domain,
      );
      last AUTH
    }

    if ($mechanism eq 'PLAIN') {
      my ($user, $passwd) = $zrequest->credentials->all;
      $result = $self->plain_authenticate(
        $zrequest->domain => $user => $passwd
      );
      last AUTH
    }

    if ($mechanism eq 'CURVE') {
      my $pubkey = $zrequest->credentials->get(0);
      $result = $self->curve_authenticate(
        $zrequest->domain => $pubkey
      );
      last AUTH
    }

    $result = POEx::ZMQ::ZAP::Result->new(
      allowed => 0,
      reason  => 'Security mechanism not supported',
      domain  => '',
    );
  } # AUTH

  if ($result->allowed) {
    $self->_send_success_reply(
      # FIXME user ids?
      $zrequest->envelope, $zrequest->request_id
    );
    my $address = $zrequest->address;
    my $domain  = $zrequest->domain;
    # FIXME emit request/result pair, make sure these are documented,
    #  maybe pull out of  ?
    $self->emit( log => auth =>
      "Successful auth from $address (domain '$domain')"
    );
  } else {
    my $reason  = $result->reason;
    $self->_send_error_reply(
      $zrequest->envelope, $zrequest->request_id, 400, $reason
    );
    my $address = $zrequest->address;
    my $domain  = $zrequest->domain;
    # FIXME emit request/result pair ?
    $self->emit( log => fail =>
      "Failed auth from $address [domain '$domain'] ($reason)"
    );
  }
}

sub _send_success_reply {
  my ($self, $envelope, $req_id, $userid) = @_;

  my @reply = $self->_assemble_reply_msg(
    request_id  => $req_id,
    status_code => 200,
    status_text => 'OK',
    (defined $userid ? (user_id => $userid) : () ),
  );

  $self->_zsock->send_multipart(
    [ $envelope, '', @reply ]
  );
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
    ZAP_VERSION,
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

=pod

FIXME document emitted 'log' events

=cut

