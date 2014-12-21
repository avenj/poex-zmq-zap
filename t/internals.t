use Test::More;
use strict; use warnings FATAL => 'all';

use List::Objects::WithUtils;
use List::Objects::Types -all;

use POEx::ZMQ::ZAP::Internal::Request;
use POEx::ZMQ::ZAP::Internal::Result;

## Request

my $req = POEx::ZMQ::ZAP::Internal::Request->new(
  envelope    => ['foo'],
  request_id  => 123,
  domain      => 'bar',
  address     => '1.2.3.4',
  mechanism   => 'PLAIN',
  credentials => ['foo', 'bar'],
);

ok is_ArrayObj $req->envelope, 'envelope coerced ok';
is_deeply [ $req->envelope->all ], ['foo'], 'envelope ok';
ok is_ArrayObj $req->credentials, 'credentials coerced ok';
is_deeply [ $req->credentials->all ], ['foo', 'bar'], 'credentials ok';
ok $req->request_id eq '123', 'request_id ok';
ok $req->domain eq 'bar', 'domain ok';
ok $req->address eq '1.2.3.4', 'address ok';
ok $req->mechanism eq 'PLAIN', 'mechanism ok';

$req = POEx::ZMQ::ZAP::Internal::Request->new(
  envelope   => ['foo'],
  request_id => 123,
  address    => '1.2.3.4',
  mechanism  => 'PLAIN',
);
ok $req->domain eq '', 'default domain ok';
ok $req->identity eq '', 'default identity ok';
ok $req->credentials->is_empty, 'default credentials ok';

eval {
  POEx::ZMQ::ZAP::Internal::Request->new(
    envelope   => [],
    address    => '1.2.3.4',
    mechanism  => 'NULL',
  );
};
like $@, qr/request_id/, 'missing request_id dies';

eval {
  POEx::ZMQ::ZAP::Internal::Request->new(
    request_id => 123,
    envelope   => [],
    address    => '1.2.3.4',
  );
};
like $@, qr/mechanism/, 'missing mechanism dies';

eval {
  POEx::ZMQ::ZAP::Internal::Request->new(
    request_id => 123,
    envelope   => [],
    mechanism  => 'NULL',
  );
};
like $@, qr/address/, 'missing address dies';

eval {
  POEx::ZMQ::ZAP::Internal::Request->new(
    request_id => 123,
    address    => '1.2.3.4',
    mechanism  => 'NULL',
  );
};
like $@, qr/envelope/, 'missing envelope dies';


## Result
my $result = POEx::ZMQ::ZAP::Internal::Result->new(
  allowed => 0,
  domain  => 'foo',
  reason  => 'because I said so',
  username => 'bar', 
);
ok !$result->allowed, 'allowed ok';
ok $result->domain eq 'foo', 'domain ok';
ok $result->reason eq 'because I said so', 'reason ok';
ok $result->username eq 'bar', 'username ok';
ok $result->has_username, 'has_username predicate ok';

eval {
  POEx::ZMQ::ZAP::Internal::Result->new(
    domain => 'foo',
  )
};
like $@, qr/allowed/, 'missing allowed dies';

eval {
  POEx::ZMQ::ZAP::Internal::Result->new(
    allowed => 1,
  )
};
like $@, qr/domain/, 'missing domain dies';

done_testing
