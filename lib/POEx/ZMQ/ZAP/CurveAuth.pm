package POEx::ZMQ::ZAP::CurveAuth;

use strictures 1;
use Carp;

use Scalar::Util 'reftype';

use Crypt::ZCert;
use Path::Tiny;

use Types::Standard       -types;
use Types::Path::Tiny     -types;
use List::Objects::Types  -types;


use Moo; use MooX::late;


has _pubkeys => (
  lazy      => 1,
  is        => 'ro',
  isa       => TypedHash[ArrayObj],
  coerce    => 1,
  builder   => sub { +{} },
);


sub _install_pubkey_from_cert {
  my ($self, $domain, $pubcert) = @_;
  my $zcert = Crypt::ZCert->new(public_file => $pubcert);
  my $pubkey = $zcert->public_key_z85;
  $self->_install_pubkey($domain => $pubkey)
}

sub _install_pubkey {
  my ($self, $domain, $pubkey) = @_;
  my @domains
    = ref $domain && reftype $domain eq 'ARRAY' ? @$domain : $domain;
  push @{ $self->_pubkeys->{ $pubkey } }, @domains;
  $self
}

sub setup_certificate {
  my ($self, $domain, $path) = @_;
  confess "Expected a domain and path to certificate or certificate directory"
    unless defined $domain and defined $path;
  $path = path($path);
  confess "No such file or directory: $path" unless $path->exists;

  if ($path->is_dir) {
    my $itr = $path->iterator;
    CERT: while (my $next = $itr->()) {
      next CERT unless -f $next and $next =~ /\.key$/;
      $self->_install_pubkey_from_cert($domain => $next)
    }
  } else {
    $self->_install_pubkey_from_cert($domain => $path)
  }
  
  $self
}

sub setup_key {
  my ($self, $domain, $pubkey) = @_;
  confess "Expected a domain and a Z85-encoded public key"
    unless defined $domain and $pubkey;
  $self->_install_pubkey($domain => $pubkey)  
}

sub check {
  my ($self, $domain, $pubkey) = @_;
  confess "Expected a domain and a public key (as Z85 text)"
    unless defined $domain and defined $pubkey;

  my $listed = $self->_pubkeys->get($pubkey);
  return unless $listed;
  return 1
    # OK if pubkey matches and we're checking against -all domains:
    if $domain eq '-all'
    # OK if matching pubkey was set up for -all domains:
    or $listed->has_any(sub { $_ eq '-all' || $_ eq $domain });
  ()
}

sub invalidate_all_keys {
  my ($self) = @_;
  $self->_pubkeys->clear;
  $self
}

sub invalidate_key {
  my ($self, $pubkey) = @_;
  $self->_pubkeys->delete($pubkey);
  $self
}

sub invalidate_domain_key {
  my ($self, $domain, $pubkey) = @_;

  my $listed = $self->_pubkeys->get($pubkey) || return;
  my $new_domains = $listed->grep(sub { $_ ne $domain });
  if ($new_domains->has_any) {
    $self->_pubkeys->set($pubkey => $new_domains)
  } else {
    $self->_pubkeys->delete($pubkey)
  }

  $self
}

sub invalidate_domain {
  my ($self, $domain) = @_;

  my $itr = $self->_pubkeys->iter;
  while (my ($pubkey, $listed) = $itr->()) {
    my $new_domains = $listed->grep(sub { $_ ne $domain });
    if ($new_domains->has_any) {
      $self->_pubkeys->set($pubkey => $new_domains)
    } else {
      # No other domains for this key
      $self->_pubkeys->delete($pubkey)
    }
  }

  $self
}

# Hrm. So I implemented this and then couldn't think of much utility.
# Here it is in case I do:
#sub invalidate_keys_for_domain {
#  my ($self, $domain) = @_;
#
#  my $itr = $self->_pubkeys->iter;
#  while (my ($pubkey, $listed) = $itr->()) {
#    $self->_pubkeys->delete($pubkey) 
#      if $listed->has_any(sub { $_ eq $domain })
#  }
#
#  $self
#}

1;

=pod

=head1 NAME

POEx::ZMQ::ZAP::CurveAuth - CURVE key management for ZeroMQ ZAP

=head1 SYNOPSIS

FIXME

=head1 DESCRIPTION

This module handles loading, managing, and validating CURVE public keys for
use with L<POEx::ZMQ::ZAP>.

The public keys may be loaded from C<ZCert>-formatted certificate files; see
L<Crypt::ZCert> for details and a certificate creation interface.

=head2 METHODS

=head1 setup_certificate

  # Add a single ZCert certificate:
  $curve->setup_certificate(mydomain => 'keys/mydomain.key');

  # Add all certificates (ending in .key) found in $dir:
  $curve->setup_certificate(mydomain => 'keys/');

  # Add a certificate to multiple domains in one shot:
  $curve->setup_certificate([qw/foo bar/], 'keys/myfoobar.key')

  # Add a certificate that applies to all domains:
  $curve->setup_certificate(-all => $path);

Takes a domain or an ARRAY of domains and a path to a single
C<ZCert>-formatted certificate or a directory containing multiple
certificates; the relevant certificates and processed and their public keys
registered for the given domain[s].

See L<Crypt::ZCert> for details regarding certificates.

=head1 setup_key

  $curve->setup_key($domain => $z85_pubkey);

Like L</setup_certificate>, but the Z85-encoded public key is passed directly.

=head1 check

  $curve->check($domain => $pubkey);

Verifies the given C<$pubkey> is valid for C<$domain> (or a matching key has
been loaded for the C<-all> domain; see L</setup_certificate>).

If the given C<$domain> is C<-all>, a matching key loaded for any domain is
considered valid.

=head1 invalidate_key

  $curve->invalidate_key($pubkey);

Invalidates the given C<$pubkey> (for all domains).

=head1 invalidate_all_keys

  $curve->invalidate_all_keys;

Invalidates all loaded keys.

=head1 invalidate_domain_key

  $curve->invalidate_domain_key($domain => $pubkey);

Invalidate the public key only for the given domain.

=head1 invalidate_domain

  $curve->invalidate_domain($domain);

Invalidates the given domain for all relevant loaded public keys.

=head1 AUTHOR

Jon Portnoy <avenj@cobaltirc.org>

=cut
