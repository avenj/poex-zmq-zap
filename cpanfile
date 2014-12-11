requires "strictures" => "1";

requires "Crypt::ZCert" => "0.003";
requires "POEx::ZMQ"    => "0.005";

requires "List::Objects::Types" => "1.003";

on 'test'      => sub {
  requires "Test::More" => "0.88";
};
