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
  # FIXME tests for multi-domain setup_* ->
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
    if $domain eq '-all'
    or $listed->has_any(sub { $_ eq '-all' || $_ eq $domain });
  return
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
