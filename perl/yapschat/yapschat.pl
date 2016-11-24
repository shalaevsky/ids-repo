#usr/bin/perl
use IO::Socket::INET;
use AnyEvent::Socket qw(tcp_server tcp_connect);
use AnyEvent::Handle();
use Socket qw(:all);
use Digest::CRC qw (crc16); 
use Crypt::CBC;
use Crypt::RSA;
use Tie::File::AsHash;
use Getopt::Std;

getopts("a:n:p:k:h",\%opt); 

if (defined $opt{h}) {
	print "-n name \t: your name \n";
	print "-a 192.168.2.1 \t\t: your ip address \n";	
	print "-p 1520 \t\t: port \n";
	print "-k key \t\t: encryption/decryption key \n";
	exit;
}



my $quit_program = AnyEvent->condvar;
my $udp_port=1520;
my $tcp_port=8081;
$udp_port=$opt{p} if (defined $opt{p});
my $name ='test1';
$name=$opt{n} if (defined $opt{n});
my $key = 'a' x 16;
$key=$opt{k} if (defined $opt{k});
my $cipher = Crypt::CBC->new( {
         'key'    => $key,
         'cipher' => 'Rijndael' #AES
     } );
tie my %banlist, 'Tie::File::AsHash', "banlist.txt", split => ':'or die "error $!";
sub initCipher {
return $cipher = Crypt::CBC->new( {'key' => $key,'cipher' => 'Rijndael'});
}

my $rsa = new Crypt::RSA; 
my ($public, $private);

my $max_len= 8192;
my $sock = IO::Socket::INET->new(LocalPort=>$udp_port,  Broadcast =>1, Proto=>'udp',  Blocking  => 0,     ReuseAddr => 1);
my $client = IO::Socket::INET->new(PeerPort  => $udp_port, PeerAddr  => inet_ntoa(INADDR_BROADCAST), Proto     => 'udp', Broadcast => 1 )
    or die "Can't bind : $@\n";
my $message = AnyEvent->condvar;

my $server_socket_watcher = AnyEvent->io(
    fh   => $sock,
    poll => 'r',
    cb   => sub {
        my $packet = '';
        $sock->recv($packet,$max_len);
        my($port, $ipaddr) = sockaddr_in($sock->peername); 
        my $ip_address = inet_ntoa($ipaddr);
        $len=unpack('x n', $packet);
        $msg=unpack("x3 A$len",$packet);
        $crc=unpack("x3 x$len n", $packet);
        return unless $crc == crc16(pack('CnA*', 0x02, $len, $msg));
        $msg=$cipher->decrypt($msg);
        $user=$1 if $msg=~/(.*)?:/;
        $users{$user}=$ip_address unless exists $users{$user}; 
        return if $user eq $name;
        return if exists($banlist{$user});        
        if ($msg=~ /(.*)?:msg:(.*)?:(.*)/) {
            if ($2 ne $name) {
            $msg='';
            } else{
            $msg="$1:private:$3\n";
            }
        }
    print "$msg";      
    },
);

my $wait_for_input = AnyEvent->io (
     fh   => \*STDIN,
     poll => "r",
     cb   => sub {
        my $input =<STDIN>;
        if ($input=~/cmd:local:(.*)/){
            my $command=$1;
            if ($command=~/bladd (.*)/) {$banlist{$1}=1}
            elsif ($command=~/blrem (.*)/) {delete ($banlist{$1})}
            elsif ($command eq 'blist'){
                print "banlist:\n";
                print "$_\n" foreach(keys(%banlist));
                }
            elsif ($command eq 'quit'){exit}
            elsif ($command eq 'genkey') {
                ($public, $private) = 
                $rsa->keygen ( 
                Identity  => $name,
                Size      => 1024,
                Filename => $name,  
                ) or die $rsa->errstr();
            }
            return;
        }
        if ($input=~/cmd:global:transfer:(.*)?:(.*)?/){
            my $user=$1;
            my $file=$2;
            my $hisip=$users{$user};
            $cipher->start('encrypting');
            open(F,"$2");
            while (read(F,$buffer,1024)) {
            $cipher->crypt($buffer);
            };
            $msg=$cipher->finish;
            my $data=pack('CnA*', 0x02, length($msg), $msg);
            $data .= pack('n', crc16($data)); 
            tcp_connect ($hisip, $tcp_port, sub {
                                                        my ($fh) = @_;
                                                        my $handle;
                                                        $handle = new AnyEvent::Handle(fh     => $fh);
                                                        on_eof => sub {$handle->destroy;};
                                                        $handle->push_write($data);
                                                        });
            return;
            };
        my $msg = "$name:";
        $msg .= $input;
        $msg = $cipher->encrypt($msg) or die "encryption failed";
        my $packet = pack('CnA*', 0x02, length($msg), $msg);
        $packet .= pack('n', crc16($packet));      
        send ($client, $packet,0);
     }
  );

my $listen_address = undef;


tcp_server ($listen_address, $tcp_port, \&server_accept_cb);

my $file;
sub server_accept_cb {
    warn "accept";
    my ( $fh, $host, $port ) = @_;
    my $handle;
    $handle = new AnyEvent::Handle(
    fh      => $fh,
    on_eof  => \&decrypt_file,
    );
    $handle->on_read( \&client_read);
    return;
};


sub client_read {
    warn "client_read";
    my $chunk = $_[0]->rbuf;
    $_[0]->rbuf = '';
    $file.=$chunk;
};

sub decrypt_file {
    warn "decrypt";
        $len=unpack('x n', $file);
        $msg=unpack("x3 A$len",$file);
        $crc=unpack("x3 x$len n", $file);
        return unless $crc == crc16(pack('CnA*', 0x02, $len, $msg));
        $msg=$cipher->decrypt($msg);
        open (my $output,">123");
        print $output $msg;
    };

$quit_program->recv;