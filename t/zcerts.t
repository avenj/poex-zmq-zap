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

  # add another domain that shares one key
  $handler->zcerts->setup_certificate(bar => 't/inc/my_keyB.key');
  $handler->zcerts->setup_certificate(bar => 't/inc/my_keyC.key');
  ok !$handler->zcerts->check(foo => $maindir_keys{C}),
    'checking pubkey belonging to wrong domain fails ok';
  ok $handler->zcerts->check(bar => $maindir_keys{B}),
    'checking pubkey shared between domains ok';
  ok $handler->zcerts->check(bar => $maindir_keys{C}),
    'checking pubkey for second domain ok';

  # check against -all domains
  ok $handler->zcerts->check(-all => $subdir_keys{D}),
    'checking pubkey against -all domains ok';
  ok !$handler->zcerts->check(-all => $should_fail),
    'checking bad pubkey against -all domains fails ok';
}

{ # setup_key($domain => $pubkey)
  my $handler = ZCertHandler->new;
  my $pubkey = Crypt::ZCert->generate_keypair->public;
  $handler->zcerts->setup_key(foo => $pubkey);
  ok $handler->zcerts->check(foo => $pubkey),
    'pubkey added via setup_key checks ok';
}

{ # invalidate_all_keys
  my $handler = ZCertHandler->new;
  $handler->zcerts->setup_certificate(foo => 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->zcerts->check(foo => $subdir_keys{F});

  $handler->zcerts->invalidate_all_keys;
  ok !$handler->zcerts->check(foo => $subdir_keys{F}),
    'checking pubkey after invalidate_all_keys fails ok';
}

{ # invalidate_key
  my $handler = ZCertHandler->new;
  $handler->zcerts->setup_certificate(foo => 't/inc/keydir');
  $handler->zcerts->setup_certificate(bar => 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->zcerts->check(foo => $subdir_keys{F})
      and  $handler->zcerts->check(bar => $subdir_keys{F});

  $handler->zcerts->invalidate_key($subdir_keys{F});
  ok !$handler->zcerts->check(foo => $subdir_keys{F}),
    'checking pubkey for domain foo after invalidate_key fails ok';
  ok !$handler->zcerts->check(bar => $subdir_keys{F}),
    'checking pubkey for domain bar after invalidate_key fails ok';

  ok $handler->zcerts->check(foo => $subdir_keys{D}),
    'other pubkeys for domain foo check ok after invalidate_key';
  ok $handler->zcerts->check(bar => $subdir_keys{D}),
    'other pubkeys for domain bar check ok after invalidate_key';
}

{ # invalidate_domain
  my $handler = ZCertHandler->new;
  $handler->zcerts->setup_certificate(foo => 't/inc/keydir');
  $handler->zcerts->setup_certificate(bar => 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->zcerts->check(foo => $subdir_keys{F})
      and  $handler->zcerts->check(bar => $subdir_keys{F});

  $handler->zcerts->invalidate_domain('foo');
  ok !$handler->zcerts->check(foo => $subdir_keys{F}),
    'checking pubkey for domain foo after invalidate_domain fails ok';
  ok $handler->zcerts->check(bar => $subdir_keys{F}),
    'checking pubkey for domain bar after invalidate_domain ok';
}

{ # invalidate_domain_key
  my $handler = ZCertHandler->new;
  $handler->zcerts->setup_certificate(foo => 't/inc/keydir');
  $handler->zcerts->setup_certificate(bar => 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->zcerts->check(foo => $subdir_keys{F})
      and  $handler->zcerts->check(bar => $subdir_keys{F});

  $handler->zcerts->invalidate_domain_key(foo => $subdir_keys{F});
  ok !$handler->zcerts->check(foo => $subdir_keys{F}),
    'checking pubkey for domain foo after invalidate_domain_key fails ok';
  ok $handler->zcerts->check(bar => $subdir_keys{F}),
    'checking pubkey for domain bar after invalidate_domain_key ok';
}

done_testing
