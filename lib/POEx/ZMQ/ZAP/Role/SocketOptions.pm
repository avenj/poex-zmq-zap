package POEx::ZMQ::ZAP::Role::SocketOptions;

use strictures 1;

use POEx::ZMQ::Constants;

use Moo::Role; use MooX::late;
requires qw/
  set_sock_opt
  get_sock_opt
/;

sub enable_plain_server {
  shift->set_sock_opt(ZMQ_PLAIN_SERVER, 1)
}

sub disable_plain_server {
  shift->set_sock_opt(ZMQ_PLAIN_SERVER, 0)
}

sub get_plain_server {
  shift->get_sock_opt(ZMQ_PLAIN_SERVER)
}

sub set_plain_username {
  shift->set_sock_opt(ZMQ_PLAIN_USERNAME, @_)
}

sub get_plain_username {
  shift->get_sock_opt(ZMQ_PLAIN_USERNAME)
}

sub set_plain_password {
  shift->set_sock_opt(ZMQ_PLAIN_PASSWORD, @_)
}

sub get_plain_password {
  shift->get_sock_opt(ZMQ_PLAIN_PASSWORD)
}

sub enable_curve_server {
  shift->set_sock_opt(ZMQ_CURVE_SERVER, 1)
}

sub disable_curve_server {
  shift->set_sock_opt(ZMQ_CURVE_SERVER, 0)
}

sub get_curve_server {
  shift->get_sock_opt(ZMQ_CURVE_SERVER)
}

sub set_curve_pubkey {
  shift->set_sock_opt(ZMQ_CURVE_PUBLICKEY, @_)  
}
{ no warnings 'once'; *set_curve_publickey = *set_curve_pubkey }

sub get_curve_pubkey {
  shift->get_sock_opt(ZMQ_CURVE_PUBLICKEY) 
}
{ no warnings 'once'; *get_curve_publickey = *get_curve_pubkey }

sub set_curve_secretkey {
  shift->set_sock_opt(ZMQ_CURVE_SECRETKEY, @_)
}

sub get_curve_secretkey {
  shift->get_sock_opt(ZMQ_CURVE_SECRETKEY)
}

sub set_curve_serverkey {
  shift->set_sock_opt(ZMQ_CURVE_SERVERKEY, @_)
}

sub get_curve_serverkey {
  shift->get_sock_opt(ZMQ_CURVE_SERVERKEY)
}

sub set_zap_domain {
  shift->set_sock_opt(ZMQ_ZAP_DOMAIN, @_)
}

sub get_zap_domain {
  shift->get_sock_opt(ZMQ_ZAP_DOMAIN)
}

sub get_current_mechanism {
  shift->get_sock_opt(ZMQ_MECHANISM)
}

1;

=pod

=head1 NAME

POEx::ZMQ::ZAP::Role::SocketOptions - Add authentication-related methods to a POEx::ZMQ::Socket

=head1 SYNOPSIS

FIXME

=head1 DESCRIPTION

A L<Moo::Role> that can be applied to a L<POEx::ZMQ::Socket> instance to add
syntactical sugar for setting and retrieving C<ZAP>-related options.

=head2 METHODS

=head3 All mechanisms

=head4 set_zap_domain

Set the domain for ZAP authentication (B<ZMQ_ZAP_DOMAIN).

Takes a string.

Setting a domain enables ZAP authentication for C<NULL> security (the default
on all C<< tcp:// >> connections).

=head4 get_zap_domain

Returns the current ZAP domain (B<ZMQ_ZAP_DOMAIN>), if present.

=head4 get_current_mechanism

Returns the current security mechanism (B<ZMQ_MECHANISM>) for the socket, as a
constant (see L<POEx::ZMQ::Constants>) -- one of: C<ZMQ_NULL>, C<ZMQ_PLAIN>,
C<ZMQ_CURVE>.

=head3 PLAIN

=head4 enable_plain_server

Enable the C<PLAIN> security role (B<ZMQ_PLAIN_SERVER>) for the socket (see
L<zmq_plain(7)>).

=head4 disable_plain_server

Disable the C<PLAIN> security role (B<ZMQ_PLAIN_SERVER>) for the socket.

=head4 get_plain_server

Returns the current boolean value of the B<ZMQ_PLAIN_SERVER> option; see
L</enable_plain_server>, L</disable_plain_server>.

=head4 set_plain_username

Set the C<PLAIN> username for outgoing connections (B<ZMQ_PLAIN_USERNAME>).

If set, the security mechanism used for outgoing connections will be C<PLAIN>.

See L</set_plain_password>.

=head4 get_plain_username

Returns the current string value of the B<ZMQ_PLAIN_USERNAME> option; see
L</set_plain_username>.

=head4 set_plain_password

Set the C<PLAIN> password for outgoing connections (B<ZMQ_PLAIN_PASSWORD>).

If set, the security mechanism used for outgoing connections will be C<PLAIN>.

See L</set_plain_username>.

=head4 get_plain_password

Returns the current string value of the B<ZMQ_PLAIN_PASSWORD> option; see
L</set_plain_password>.

=head3 CURVE

=head4 enable_curve_server

Enable the C<CURVE> security role (B<ZMQ_CURVE_SERVER>) for the socket (see
L<zmq_curve(7)>.

=head4 disable_curve_server

Disable the C<CURVE> security role (B<ZMQ_CURVE_SERVER>) for the socket (see
L<zmq_curve(7)>.

=head4 get_curve_server

Returns the current boolean value of the B<ZMQ_CURVE_SERVER> option; see
L</enable_curve_server>, L</disable_curve_server>.

=head4 set_curve_pubkey

Set the socket's long term C<CURVE> public key (B<ZMQ_CURVE_PUBLICKEY>), as
binary or C<Z85>-encoded text (see L<Crypt::ZCert>).

=head4 get_curve_pubkey

Returns the current value of the B<ZMQ_CURVE_PUBLICKEY> option; see
L</set_curve_publickey>.

=head4 set_curve_secretkey

Set the socket's long term C<CURVE> secret key (B<ZMQ_CURVE_SECRETKEY>).

FIXME clarify key types

=head4 get_curve_secretkey

FIXME

=head4 set_curve_serverkey

FIXME

=head4 get_curve_serverkey

FIXME

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
