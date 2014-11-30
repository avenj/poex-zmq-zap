package POEx::ZMQ::ZAP::PlainAuth;

use strictures 1;
use Carp;

use Scalar::Util 'reftype';

use Types::Standard       -types;
use List::Objects::Types  -types;


use Moo; use MooX::late;

has _users => (
  #  $username => InflatedHash(
  #    pass => $passwd,
  #    domains => array(@domains),
  #  )
  lazy      => 1,
  is        => 'ro',
  isa       => TypedHash[ InflatedHash[qw/pass domains/] ],
  coerce    => 1,
  builder   => sub { +{} },
);

sub setup_user {
  my ($self, $domain, $user, $passwd) = @_;
  confess "Expected a domain, username, and passwd"
    unless defined $domain and defined $user and defined $passwd;

  my @domains
    = ref $domain && reftype $domain eq 'ARRAY' ? @$domain : $domain;
  $self->_users->set( $user =>
    hash( pass => $passwd, domains => array(@domains) )->inflate
  );

  $self
}

sub check_login {
  my ($self, $domain, $user, $passwd) = @_;
  confess "Expected a domain, username, and passwd"
    unless defined $domain and defined $user and defined $passwd;

  my $uobj = $self->_users->get($user);
  confess "No such user '$user' available" unless $uobj;
  
  $uobj->pass eq $passwd and $uobj->domains->has_any(sub { $_ eq $domain })
}

sub add_user_domain {
  my ($self, $user, $domain) = @_;
  confess "Expected a username and domain"
    unless defined $user and defined $domain;

  my $uobj = $self->_users->get($user);
  confess "No such user '$user' available" unless $uobj;
  $uobj->domains->push($domain)
    unless $uobj->domains->has_any(sub { $_ eq $domain });

  $self
}

sub set_passwd {
  my ($self, $user, $passwd) = @_;
  confess "Expected a username and password"
    unless defined $user and defined $passwd;

  my $uobj = $self->_users->get($user);
  confess "No such user '$user' available, perhaps you meant 'setup_user'?"
    unless $uobj;
  $self->_users->set( $user =>
    hash( pass => $passwd, domains => $uobj->domains )->inflate
  );

  $self
}

sub invalidate_user_domain {
  my ($self, $user, $domain) = @_;
  confess "Expected a username and domain"
    unless defined $user and defined $domain;

  my $uobj = $self->_users->get($user);
  confess "No such user '$user' available" unless $uobj;
  my $domains = $uobj->domains->grep(sub { $_ ne $domain });
  $self->_users->set( $user =>
    hash( pass => $uobj->passwd, domains => $domains )->inflate
  );

  $self
}

sub invalidate_domain {
  my ($self, $domain) = @_;
  confess "Expected a domain" unless defined $domain;
  
  $self->_users->keys->visit(sub {
    my $user = $_;
    my $uobj = $self->_users->get($user);
    if ( $uobj->domains->has_any(sub { $_ eq $domain }) ) {
      $self->_users->set( $user =>
        hash(
          pass    => $uobj->passwd,
          domains => $uobj->domains->grep(sub { $_ ne $domain }),
        )->inflate
      );
    }
  });
  
  $self
}

sub invalidate_user {
  my ($self, $user) = @_;
  unless ( $self->_users->delete($user)->has_any ) {
    carp "Cannot invalidate_user for nonexistant user '$user'"
  }
  $self
}

1;
