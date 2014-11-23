package POEx::ZMQ::ZAP;


use Moo; use MooX::late;
with
  'POEx::ZMQ::ZAP::Role::Whitelisting',
  'POEx::ZMQ::ZAP::Role::Blacklisting',
  'POEx::ZMQ::ZAP::Role::PlainHandler',
  'POEx::ZMQ::ZAP::Role::ZCertHandler',
;

# FIXME
# basic
#  - one ZAP handler per proc (AtFork magic?)
#  - handler provides one inproc ROUTER inproc://zeromq.zap.01
#    any number of servers talk to handler via inproc DEALER
#

sub _parse_request_msg {
  my ($self, $parts) = @_;
  my $envelope = $parts->items_before(sub { ! length });
  my $body     = $parts->items_after(sub { ! length });

  my (
    $version,
    $req_id,
    $domain,
    $address,
    $identity,
    $mechanism,
    @credentials
  ) = $body->all;

  # request parts:
  #   zero-length delim
  #    version frame (three bytes '1.0')
  #    request id    (binary blob) [optional]
  #    domain        (string)
  #    address       
  #    identity
  #    mechanism     (string)
  #    credentials   (zero or more binary blob parts)
}


sub _assemble_reply_msg {

# reply parts:
#   zero-length delim
#    version frame (three bytes '1.0')
#    request id    (binary blob) [optional]
#    status code   (string)
#    status text   (string)  [optional]
#    user id       (string)
#    metadata      (binary blob) [optional]

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
