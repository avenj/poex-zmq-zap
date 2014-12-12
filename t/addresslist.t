use Test::More;
use strict; use warnings FATAL => 'all';

{ package AddrHandler;
  use Moo;
  with 'POEx::ZMQ::ZAP::Role::AddressHandler';
}

eval {; AddrHandler->new(address_auth_via => 'foo') };
ok $@, 'bad address_auth_via dies';

# blacklist
my $blacklist = AddrHandler->new;
cmp_ok $blacklist->address_auth_via, 'eq', 'blacklist',
  'AddressHandler defaults to blacklist mode ok';

eval {; $blacklist->allow_mask('*') };
like $@, qr/blacklist/, 'attempted allow_mask in blacklist mode dies';

# glob-y masks
$blacklist->deny_mask('1.2.3.*');
$blacklist->deny_mask('10.0.?.?');
ok $blacklist->addr_is_blacklisted('1.2.3.4'),  'blacklist match 1 ok';
ok $blacklist->addr_is_blacklisted('10.0.0.1'), 'blacklist match 2 ok';
ok !$blacklist->addr_is_blacklisted('10.0.123.4'),
  'blacklist failed match ok';
ok !$blacklist->addr_is_whitelisted('1.2.3.4'),
  'blacklist returns false for arbitrary whitelist queries ok';

# regex masks
$blacklist->deny_mask(qr/^127.0.0.[0123]$/);
ok $blacklist->addr_is_blacklisted('127.0.0.1'), 'blacklist regex match 1 ok';
ok !$blacklist->addr_is_blacklisted('127.0.0.9'), 
  'blacklist failed regex match ok';

# whitelist
my $whitelist = AddrHandler->new(address_auth_via => 'whitelist');
eval {; $whitelist->deny_mask('*') };
like $@, qr/whitelist/, 'attempted deny_mask in whitelist mode dies';

done_testing
