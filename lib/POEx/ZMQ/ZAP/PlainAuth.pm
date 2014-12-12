package POEx::ZMQ::ZAP::PlainAuth;

use strictures 1;
use Carp;

use Scalar::Util 'reftype';

use List::Objects::WithUtils;

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

sub check {
  my ($self, $domain, $user, $passwd) = @_;
  confess "Expected a domain, username, and passwd"
    unless defined $domain and defined $user and defined $passwd;

  confess "->check for special domain '-all' disallowed"
    if $domain eq '-all';

  my $uobj = $self->_users->get($user);
  return unless $uobj;  
  
  $self->compare_passwd($passwd, $uobj->pass)
    and $uobj->domains->has_any(sub { $_ eq '-all' || $_ eq $domain })
}

sub compare_passwd {
  # Overridable
  my ($self, $given, $expected) = @_;
  confess "Expected a given & expected password string"
    unless defined $given and defined $expected;
  $given eq $expected
}

sub add_domain_to_user {
  my ($self, $domain, $user) = @_;
  confess "Expected a domain and username"
    unless defined $domain and defined $user;

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

sub invalidate_domain_user {
  my ($self, $domain, $user) = @_;
  confess "Expected a domain and username"
    unless defined $domain and defined $user;

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
  confess "Expected a username" unless defined $user;
  unless ( $self->_users->delete($user)->has_any ) {
    carp "Cannot invalidate_user for nonexistant user '$user'"
  }
  $self
}

sub invalidate_all_users {
  my ($self) = @_;
  $self->_users->clear;
  $self
}

1;
