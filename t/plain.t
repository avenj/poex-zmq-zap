use Test::More;
use strict; use warnings FATAL => 'all';

{ package PlainHandler;
  use Moo; with 'POEx::ZMQ::ZAP::Role::PlainHandler';
}

# FIXME tests for '-all'

# setup_user
my $handler = PlainHandler->new;
isa_ok $handler->plain, 'POEx::ZMQ::ZAP::PlainAuth';
$handler->plain_setup_user( foo => userA => 'somepass' );
$handler->plain->setup_user( foo => userB => 'otherpass' );

eval {; $handler->plain->setup_user( foo => 'userC' ) };
ok $@, 'bad args to setup_users dies';

# check
ok $handler->plain_check( foo => userA => 'somepass' ),
  'delegated plain_check ok';
ok $handler->plain->check( foo => userB => 'otherpass' ),
  'plain->check ok';

eval {; $handler->plain->check( foo => 'userA' ) };
ok $@, 'bad args to check dies';

ok !$handler->plain->check( bar => userA => 'somepass' ),
  'check fails for unknown domain ok';
ok !$handler->plain->check( foo => userC => 'somepass' ),
  'check fails for unknown user ok';
ok !$handler->plain->check( foo => userA => 'badpass' ),
  'check fails for bad passwd ok';

# add_domain_to_user
$handler->plain->add_domain_to_user( bar => 'userA' );
ok $handler->plain_check( bar => userA => 'somepass' ),
  'check (new) after add_domain_to_user ok';
ok $handler->plain_check( foo => userA => 'somepass' ),
  'check (prev) after add_domain_to_user ok';

eval {; $handler->plain->add_domain_to_user( bar => 'nosuch' ) };
ok $@, 'attempting to add_domain_to_user for nonexistant user dies';

# set_passwd
$handler->plain->set_passwd( userA => 'newpass' );
ok $handler->plain_check( foo => userA => 'newpass' ),
  'check after set_passwd ok';
ok !$handler->plain_check( foo => userA => 'somepass' ),
  'old passwd fails after set_passwd ok';

eval {; $handler->plain->set_passwd( nosuch => 'somepass' ) };
ok $@, 'attempting to set_passwd for nonexistant user dies';

# invalidate_domain

# invalidate_user

# invalidate_domain_user

# invalidate_all_users


done_testing
