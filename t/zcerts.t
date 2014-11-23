use Test::More;
use strict; use warnings FATAL => 'all';

{ package ZCertHandler;
  use Moo; with 'POEx::ZMQ::ZAP::Role::ZCertHandler';
}


use Crypt::ZCert;

my (%maindir_keys, %subdir_keys);
for (qw/A B C/) {
  my $zcert = Crypt::ZCert->new(
    public_file => join('', "t/inc/my_key", $_, ".key"),
    secret_file => join('', "t/inc/my_key", $_, ".key_secret"),
  );
  $maindir_keys{$_} = $zcert->public_key_z85
}
for (qw/D E F/) {
  my $zcert = Crypt::ZCert->new(
    public_file => join('', "t/inc/keydir/my_key", $_, ".key"),
    secret_file => join('', "t/inc/keydir/my_key", $_, ".key_secret"),
  );
  $subdir_keys{$_} = $zcert->public_key_z85
}



{ # setup_certificate($domain => $dir)
  my $handler = ZCertHandler->new;
  isa_ok $handler->zcerts, 'POEx::ZMQ::ZAP::ZCerts';

  $handler->zcerts->setup_certificate(foo => 't/inc/keydir');

  # check($domain => $pubkey) [for keys added from dir]
  my $should_fail = $maindir_keys{A};
  ok !$handler->zcerts->check(foo => $should_fail),
    'bad pubkey fails ok';
  for my $name (keys %subdir_keys) {
    my $pubkey = $subdir_keys{$name};
    ok $handler->zcerts->check(foo => $pubkey),
      "good pubkey ($name) checks ok";
    ok !$handler->zcerts->check(bar => $pubkey),
      "good pubkey ($name) but bad domain fails ok";
  }

  # add another file & recheck
  $handler->zcerts->setup_certificate(foo => 't/inc/my_keyB.key');
  ok $handler->zcerts->check(foo => $maindir_keys{B}),
    'adding another pubkey from file ok';
  ok $handler->zcerts->check(foo => $subdir_keys{D}),
    'previously added pubkey still works ok';
}


# FIXME
#   shove some pubkeys in a dir
# test setup_certificate(-all => $cert);
# test setup_key($domain => $pubkey)
#
# test check(-all => $pubkey);
# test check($domain => $pubkey);
#
# test invalidate_key
# test invalidate_domain
# test invalidate_keys_for_domain
# test invalidate_all_keys

done_testing
