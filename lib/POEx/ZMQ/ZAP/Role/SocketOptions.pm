package POEx::ZMQ::ZAP::Role::SocketOptions;

use POEx::ZMQ::Constants;

use Moo::Role; use MooX::late;
requires qw/
  set_sock_opt
  get_sock_opt
/;

# FIXME audit to make sure we have string trans for these

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

sub get_curve_secrekey {
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
