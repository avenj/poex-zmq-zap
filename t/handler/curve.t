use Test::More;
use strict; use warnings FATAL => 'all';


my $Got = +{};
my $Expected = +{

};


use POE;
use POEx::ZMQ;
use POEx::ZMQ::ZAP::Handler;

use File::Temp ();
my $tempdir = File::Temp::tempdir(CLEANUP => 1);
my $endpt = "ipc://$tempdir/test-zmq-zap-$$";


POE::Session->create(
  package_states => main => [qw/
    _start
    zmq_recv_multipart
    timeout
  / ],
);

sub timeout {
  $_[KERNEL]->alarm_remove_all;
  fail "Timed out!";
  diag explain $Got;
  exit 1
}

sub _start {
  $_[KERNEL]->sig(ALRM => 'timeout');
  my $zmq = $_[HEAP]->{zmq} = POEx::ZMQ->new;
  my $rtr = $_[HEAP]->{rtr} = $zmq->socket(type => ZMQ_ROUTER);
  $rtr->start;
  # FIXME set up auth bits
  $rtr->bind($endpt);
}

sub zmq_recv_multipart {

}

POE::Kernel->run;

is_deeply $Got, $Expected, 'handler tests ok'
  or diag explain $Got;

done_testing
