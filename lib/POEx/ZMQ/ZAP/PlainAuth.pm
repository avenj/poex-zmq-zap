package POEx::ZMQ::ZAP::PlainAuth;

use strictures 1;
use Carp;

use Scalar::Util 'reftype';

use List::Objects::WithUtils;

use Types::Standard       -types;
use List::Objects::Types  -types;

# FIXME domains_for_user, userlist


use Moo; use MooX::late;

has _users => (
  #  $username => InflatedHash(
  #    pass => $pass,
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

  confess "Attempting to setup_user for previously existing user $user"
    if $self->_users->exists($user);

  my @domains
    = ref $domain && reftype $domain eq 'ARRAY' ? @$domain : $domain;
  $self->_users->set( $user =>
    hash( pass => $passwd, domains => array(@domains) )->inflate
  );

  $self
}

sub userlist {
  my ($self, $regex) = @_;
  if ($regex) {
    confess "Expected a Regexp type object (qr//) but got $regex"
      unless ref $regex eq 'Regexp';
    return $self->_users->keys->grep(sub { m/$regex/ })->all
  }
  $self->_users->keys->all
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
    hash( pass => $uobj->pass, domains => $domains )->inflate
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
          pass    => $uobj->pass,
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

=pod

=head1 NAME

POEx::ZMQ::ZAP::PlainAuth - PLAIN user management for ZeroMQ ZAP

=head1 SYNOPSIS

FIXME

=head1 DESCRIPTION

This module handles adding, removing, and authenticating C<PLAIN>
user/password pairs for use with L<POEx::ZMQ::ZAP> via
L<POEx::ZMQ::ZAP::Role::PlainHandler>.

=head2 METHODS

=head1 setup_user

  $plain->setup_user($domain => $username => $passwd);

FIXME

=head1 check

  $plain->check($domain => $username => $passwd);

FIXME

Calls L</compare_passwd> to perform password comparison; by default, this is
a simple check for string equality. See L</compare_passwd> regarding using
hashed passwords.

=head1 compare_passwd

  $plain->compare_passwd($given => $expected);

Called internally to compare passwords.

C<compare_passwd> can be overriden or monkey-patched to modify the way
passwords are compared; for example, when comparing against stored hashes:

  use App::bmkpasswd 'passwdcmp';
  use Class::Method::Modifiers 'install_modifier';
  install_modifier 'POEx::ZMQ::ZAP::PlainAuth' => around => compare_passwd =>
    sub {
      my ($orig, $self, $given, $crypted) = @_;
      # Works for bcrypt, SHA, MD5:
      passwdcmp $given => $crypted
    };

=head1 userlist

  # Get all known usernames:
  my @all_users = $plain->userlist;
  # Get all usernames containing 'foo':
  my @matches = $plain->userlist( qr/foo/ );

Given no arguments, returns a list of known usernames.

Given a C<Regexp>-type object, returns a list of known usernames that match
the given pattern.

=head1 add_domain_to_user

  $plain->add_domain_to_user($domain => $username);

Add a new domain for an existing user.

=head1 set_passwd

  $plain->set_passwd($username => $passwd);

Change an existing user's password.

=head1 invalidate_domain_user

  $plain->invalidate_domain_user($domain => $username);

Invalidates a user for a specific domain only.

=head1 invalidate_domain

  $plain->invalidate_domain($domain);

Invalidate a given domain.

=head1 invalidate_user

  $plain->invalidate_user($username);

Invalidate a given username for all domains.

=head1 invalidate_all_users

  $plain->invalidate_all_users;

Clear the user list entirely.

=cut
