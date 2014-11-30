use Test::More;
use strict; use warnings FATAL => 'all';

{ package CurveHandler;
  use Moo; with 'POEx::ZMQ::ZAP::Role::CurveHandler';
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
  my $handler = CurveHandler->new;
  isa_ok $handler->curve, 'POEx::ZMQ::ZAP::CurveAuth';

  # handler: curve_setup_certificate
  ok $handler->curve_setup_certificate(foo => 't/inc/keydir')
    == $handler->curve,
    'curve_setup_certificate returned self ok';

  # check($domain => $pubkey) [for keys added from dir]
  my $should_fail = $maindir_keys{A};
  ok !$handler->curve->check(foo => $should_fail),
    'bad pubkey fails ok';
  for my $name (keys %subdir_keys) {
    my $pubkey = $subdir_keys{$name};
    ok $handler->curve->check(foo => $pubkey),
      "good pubkey ($name) checks ok";
    ok !$handler->curve->check(bar => $pubkey),
      "good pubkey ($name) but bad domain fails ok";
  }

  # add another file & recheck
  $handler->curve->setup_certificate(foo => 't/inc/my_keyB.key');
  ok $handler->curve->check(foo => $maindir_keys{B}),
    'adding another pubkey from file ok';
  ok $handler->curve->check(foo => $subdir_keys{D}),
    'previously added pubkey still works ok';

  # add another domain that shares one key
  $handler->curve->setup_certificate(bar => 't/inc/my_keyB.key');
  $handler->curve->setup_certificate(bar => 't/inc/my_keyC.key');
  ok !$handler->curve->check(foo => $maindir_keys{C}),
    'checking pubkey belonging to wrong domain fails ok';
  ok $handler->curve->check(bar => $maindir_keys{B}),
    'checking pubkey shared between domains ok';
  ok $handler->curve->check(bar => $maindir_keys{C}),
    'checking pubkey for second domain ok';

  # set up a cert for -all domains
  $handler->curve->setup_certificate(-all => 't/inc/my_keyC.key');
  ok $handler->curve->check(foo => $maindir_keys{C}),
    'checking pubkey applied to -all for specific domain ok';

  # check against -all domains
  ok $handler->curve->check(-all => $subdir_keys{D}),
    'checking pubkey against -all domains ok';
  ok !$handler->curve->check(-all => $should_fail),
    'checking bad pubkey against -all domains fails ok';

  eval {; $handler->curve_setup_certificate('foo') };
  ok $@, 'curve_setup_certificate bad args dies';
  eval {; $handler->curve->check('foo') };
  ok $@, 'check bad args dies';
}

{ # setup_key($domain => $pubkey)
  my $handler = CurveHandler->new;
  my $pubkey = Crypt::ZCert->generate_keypair->public;
  # handler: curve_setup_key
  ok $handler->curve_setup_key(foo => $pubkey) == $handler->curve,
    'curve_setup_key returned self ok';
  # handler: curve_check
  ok $handler->curve_check(foo => $pubkey),
    'pubkey added via setup_key checks ok';

  eval {; $handler->curve_setup_key('foo') };
  ok $@, 'curve_setup_key bad args dies';
}

{ # invalidate_all_keys
  my $handler = CurveHandler->new;
  # multi-domain ARRAY in setup_certificate
  $handler->curve->setup_certificate([qw/foo bar/], 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->curve->check(foo => $subdir_keys{F})
      and  $handler->curve->check(bar => $subdir_keys{F});

  ok $handler->curve->invalidate_all_keys == $handler->curve,
    'invalidate_all_keys returned self ok';
  ok !$handler->curve->check(foo => $subdir_keys{F}),
    'checking pubkey for domain foo after invalidate_all_keys fails ok';
  ok !$handler->curve->check(bar => $subdir_keys{F}),
    'checking pubkey for domain bar after invalidate_all_keys fails ok';
}

{ # invalidate_key
  my $handler = CurveHandler->new;
  $handler->curve->setup_certificate(foo => 't/inc/keydir');
  $handler->curve->setup_certificate(bar => 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->curve->check(foo => $subdir_keys{F})
      and  $handler->curve->check(bar => $subdir_keys{F});

  ok $handler->curve->invalidate_key($subdir_keys{F}) == $handler->curve,
    'invalidate_key returned self ok';
  ok !$handler->curve->check(foo => $subdir_keys{F}),
    'checking pubkey for domain foo after invalidate_key fails ok';
  ok !$handler->curve->check(bar => $subdir_keys{F}),
    'checking pubkey for domain bar after invalidate_key fails ok';

  ok $handler->curve->check(foo => $subdir_keys{D}),
    'other pubkeys for domain foo check ok after invalidate_key';
  ok $handler->curve->check(bar => $subdir_keys{D}),
    'other pubkeys for domain bar check ok after invalidate_key';

  eval {; $handler->curve->invalidate_key };
  ok $@, 'invalidate_key bad args dies';
}

{ # invalidate_domain
  my $handler = CurveHandler->new;
  $handler->curve->setup_certificate(foo => 't/inc/keydir');
  $handler->curve->setup_certificate(bar => 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->curve->check(foo => $subdir_keys{F})
      and  $handler->curve->check(bar => $subdir_keys{F});

  ok $handler->curve->invalidate_domain('foo') == $handler->curve,
    'invalidate_domain returned self ok';
  ok !$handler->curve->check(foo => $subdir_keys{F}),
    'checking pubkey for domain foo after invalidate_domain fails ok';
  ok $handler->curve->check(bar => $subdir_keys{F}),
    'checking pubkey for domain bar after invalidate_domain ok';

  eval {; $handler->curve->invalidate_domain };
  ok $@, 'invalidate_domain bad args dies';
}

{ # invalidate_domain_key
  my $handler = CurveHandler->new;
  $handler->curve->setup_certificate(foo => 't/inc/keydir');
  $handler->curve->setup_certificate(bar => 't/inc/keydir');
  fail "setup phase for invalidate checks failed, key F invalid"
    unless $handler->curve->check(foo => $subdir_keys{F})
      and  $handler->curve->check(bar => $subdir_keys{F});

  ok $handler->curve->invalidate_domain_key(foo => $subdir_keys{F})
    == $handler->curve,
    'invalidate_domain_key returned self ok';
  ok !$handler->curve->check(foo => $subdir_keys{F}),
    'checking pubkey for domain foo after invalidate_domain_key fails ok';
  ok $handler->curve->check(bar => $subdir_keys{F}),
    'checking pubkey for domain bar after invalidate_domain_key ok';

  eval {; $handler->curve->invalidate_domain_key('foo') };
  ok $@, 'invalidate_domain_key bad args dies';
}

done_testing
