requires "perl"       => "5.016";
requires "strictures" => "1";

requires "Crypt::ZCert" => "0.003";
requires "POEx::ZMQ"    => "0.005";

requires "Moo"                  => "1";
requires "MooX::late"           => "0.014";

requires "POE"                      => 1;
requires "MooX::Role::POE::Emitter" => 0;

requires "List::Objects::WithUtils" => "2";
requires "List::Objects::Types" => "1.003";

requires "Types::Standard"      => "1";

requires "Path::Tiny"           => "0";
requires "Types::Path::Tiny"    => "0";

on 'test'      => sub {
  requires "Test::More" => "0.96";
};
