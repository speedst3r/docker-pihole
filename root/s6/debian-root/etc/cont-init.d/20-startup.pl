#!/usr/bin/with-contenv perl

use 5.010;
use strict;
use warnings;
no warnings "experimental";

use Carp qw(carp croak);
use Data::Dumper;
use File::Find;

###############################################################################

{   package Cvar;

    sub env ($$;\%) {
        my ($class, $name, %env) = @_;
        %env = %ENV unless %env;

        return bless {
            _type => "env",
            _name => $name,
            _env  => \%env
        }, $class;
    }

    sub lit ($$$) {
        my ($class, $val) = @_;

        return bless {
            _type => "lit",
            _val  => $val
        }, $class;
    }

    sub name {
        my $self = shift;
        return ($self->{_type} eq "env") ?
            $self->{_name} :
            undef;
    }

    sub val {
        my $self = shift;
        return ($self->{_type} eq "env") ?
            $self->{_env}{$self->{_name}} :
            $self->{_val};
    }

    sub exists {
        my $self = shift;
        return ($self->{_type} eq "env") ?
            exists $self->{_env}{$self->{_name}} :
            defined $self->{_val};
    }
}

###############################################################################

my %FILES;
my $PIHOLE_CONF  = "/etc/pihole/setupVars.conf";
my $FTL_CONF     = "/etc/pihole/pihole-FTL.conf";
my $DNSMASQ_CONF = "/etc/dnsmasq.d/01-pihole.conf";

sub env ($;\%)  { return Cvar->env(@_); }
sub lit ($)     { return Cvar->lit(@_); }

sub configure ($$$$@);
sub configure_admin_email ($);
sub configure_blocklists ();
sub configure_dhcp ();
sub configure_dns_defaults ();
sub configure_dns_hostname ($$@);
sub configure_dns_fqdn ($);
sub configure_dns_priv ($);
sub configure_dns_dnssec ($);
sub configure_dns_forwarding ($$$$);
sub configure_dns_interface ($$);
sub configure_dns_upstream ($@);
sub configure_dns_user ($);
sub configure_ftl ($$$@);
sub configure_network (\%$$);
sub configure_pihole ($$$@);
sub configure_temperature ($);
sub configure_web_address ($$$);
sub configure_web_fastcgi ($$);
sub configure_web_password ($$);
sub configure_whitelists ();
sub do_or_die (@);
sub explain (@);
sub fix_capabilities ($);
sub fix_permissions ($);
sub mask ($$);
sub print_env(\%);
sub read_file ($);
sub sed (&$@);
sub set_defaults (\%);
sub test_configuration ($);
sub trim ($);
sub validate ($$$@);
sub validate_ip ($);
sub write_file ($@);

###############################################################################

sub configure ($$$$@) {
    my $path  = shift;
    my $name  = shift; # Variable name written to output
    my $reqd  = shift;
    my $cvar  = shift;
    my @allow = @_;

    validate($name, $reqd, $cvar, @allow);

    my @conf = grep {!/^$name=/} read_file($path);
    push @conf, "$name=" . ($cvar->val() // "");
    chomp @conf;

    write_file($path, @conf);
}

sub configure_admin_email ($) {
    my ($email) = @_;
    do_or_die("pihole", "-a", "-e", $email->val()) if $email->exists();
}

sub configure_blocklists () {
    my $path = "/etc/pihole/adlists.list";
    return if -f $path;

    my @items = ();
    push @items, "https://dbl.oisd.nl/\n";
    write_file($path, @items);
}

sub configure_dhcp() {
}

sub configure_dns_defaults () {
    do_or_die("cp", "-f", "/etc/.pihole/advanced/01-pihole.conf", $DNSMASQ_CONF);
}

sub configure_dns_hostname ($$@) {
    my $ipv4 = shift;
    my $ipv6 = shift;
    my @names = @_;

    my @dnsmasq = read_file($DNSMASQ_CONF);
    @dnsmasq    = grep {!/local\.list/} @dnsmasq;

    write_file($DNSMASQ_CONF, @dnsmasq);
}

sub configure_dns_fqdn ($) {
    my ($fqdn) = @_;

    configure_pihole("DNS_FQDN_REQUIRED", 0, $fqdn, "true", "false");

    my @dnsmasq = grep {!/^domain-needeed/} read_file($DNSMASQ_CONF);
    push @dnsmasq, "domain-needed"
        unless ($fqdn->exists() and $fqdn->val() eq "false");

    write_file($DNSMASQ_CONF, @dnsmasq);
}

sub configure_dns_priv ($) {
    my ($priv) = @_;

    configure_pihole("DNS_BOGUS_PRIV", 0, $priv, "true", "false");

    my @dnsmasq = grep {!/^bogus-priv/} read_file($DNSMASQ_CONF);
    push @dnsmasq, "bogus-priv"
        unless ($priv->exists() and $priv->val() eq "false");

    write_file($DNSMASQ_CONF, @dnsmasq);
}

sub configure_dns_dnssec ($) {
    my ($dnssec) = @_;

    configure_pihole("DNSSEC", 0, $dnssec, "true", "false");

    my @dnsmasq = read_file($DNSMASQ_CONF);
    @dnsmasq    = grep {!/^dnssec/} @dnsmasq;
    @dnsmasq    = grep {!/^trust-anchor=/} @dnsmasq;

    if ($dnssec->exists() and $dnssec->val() eq "true") {
        push @dnsmasq, "dnssec";
        push @dnsmasq, "trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
    }

    write_file($DNSMASQ_CONF, @dnsmasq);
}

sub configure_dns_forwarding ($$$$) {
    my ($enable, $upstream, $network, $domain) = @_;

    my @pihole  = read_file($PIHOLE_CONF);
    @pihole     = grep {!/^REV_SERVER/}  @pihole;
    @pihole     = grep {!/^CONDITIONAL/} @pihole;

    my @dnsmasq = read_file($DNSMASQ_CONF);
    @dnsmasq    = grep {!/^rev-server=/} @dnsmasq;
    @dnsmasq    = grep {!/^server=/}     @dnsmasq;

    if ($enable->exists() and $enable->val() eq "true")  {
        validate("REV_SERVER_TARGET", 1, $upstream);#, \&validate_ip);    TODO
        validate("REV_SERVER_CIDR",   1, $network);#,  \&validate_cidr);

        push @pihole, "REV_SERVER=true";
        push @pihole, "REV_SERVER_CIDR=".$network->val();
        push @pihole, "REV_SERVER_TARGET=".$upstream->val();
        push @pihole, "REV_SERVER_DOMAIN=".($domain->val() // "");

        push @dnsmasq, sprintf("rev-server=%s,%s", $network->val(), $upstream->val());
        push @dnsmasq, sprintf("server=/%s/%s",    $domain->val(),  $upstream->val())
            if ($domain->exists() and $domain->val());
    }

    write_file($DNSMASQ_CONF, @dnsmasq);
    write_file($PIHOLE_CONF,  @pihole);
}

sub configure_dns_interface ($$) {
    my ($iface, $listen) = @_;

    configure_pihole("PIHOLE_INTERFACE", 0, $iface);
    configure_pihole("DNSMASQ_LISTENING", 0, $listen, "all", "local", "iface");

    my @dnsmasq = read_file($DNSMASQ_CONF);
    @dnsmasq    = grep {!/^interface=/} @dnsmasq;
    @dnsmasq    = grep {!/^local-service/} @dnsmasq;
    @dnsmasq    = grep {!/^except-interface=/} @dnsmasq;

    given ($listen->val() // "all") {
        when ("all")    { push @dnsmasq, "except-interface=nonexisting"; }
        when ("local")  { push @dnsmasq, "local-service";                }
        when ("iface")  {
            $iface->exists() or croak(sprintf("%s must be set when %s is '%s'",
                $iface->name(), $listen->name(), $listen->val()));
            push @dnsmasq, "interface=".$iface->val();
        }
    }

    write_file($DNSMASQ_CONF, @dnsmasq);
}

sub configure_dns_upstream ($@) {
    my @dnsmasq = grep {!/^server=/}      read_file($DNSMASQ_CONF);
    my @pihole  = grep {!/PIHOLE_DNS_\d/} read_file($PIHOLE_CONF);
    my $count   = 0;


    foreach $_ (@_) {
        next unless $_->exists();
        # validate_ip($_); TODO Need to remove optional port number

        push @pihole, sprintf("PIHOLE_DNS_%s=%s", ++$count, $_->val());
        push @dnsmasq, "server=".$_->val();
        $count ++;
    }

    # No values given (or all were empty)
    validate("PIHOLE_DNS_1", 1, $_[0]) unless $count;

    write_file($PIHOLE_CONF,  @pihole);
    write_file($DNSMASQ_CONF, @dnsmasq);
}

sub configure_dns_user ($) {
    my ($dns_user) = @_;

    # Erase any user= directives in config snippet files
    find(sub {
        write_file($_, grep {!/^user=/} read_file($_)) if -f;
    }, "/etc/dnsmasq.d");

    configure("/etc/dnsmasq.conf", "user", 1, $dns_user);
}

sub configure_ftl ($$$@) {
    return &configure($FTL_CONF, @_);
}

sub configure_network (\%$$) {
    my ($env, $ipv4, $ipv6) = @_;
    my %env = %{$env};

    if ($ipv4->exists() and $ipv4->val() eq "auto") {
        my $output = `ip route get 1.1.1.1` or
            explain("ip route get 1.1.1.1");

        my ($gw) = $output =~ m/via\s+([^\s]+)/;
        my ($if) = $output =~ m/dev\s+([^\s]+)/;
        my ($ip) = $output =~ m/src\s+([^\s]+)/;

        $env{"PIHOLE_IPV4_ADDRESS"} = $ip;
    }

    validate_ip(env("PIHOLE_IPV4_ADDRESS"));
    configure_pihole("IPV4_ADDRESS", 1, env("PIHOLE_IPV4_ADDRESS"));

    # TODO
    if ($ipv6->exists() and $ipv6->val() eq "auto") {
        my $output = `ip route get 2606:4700:4700::1001 2>/dev/null`
            or return;

        my ($gw) = $output =~ m/via\s+([^\s]+)/;
        my ($if) = $output =~ m/dev\s+([^\s]+)/;
        my ($ip) = $output =~ m/src\s+([^\s]+)/;

        # TODO sanitize
        my @output = `ip -6 addr show dev '$if'`
            or explain("ip -6 addr show dev '$if'");

        my @gua = (); # global unique addresses
        my @ula = (); # unique local addresses
        my @ll  = (); # link local addresses

        foreach (grep {/inet6/} @output) {
            my ($ip) = m{inet6\s+([^/])+/};
            my ($chazwazza) = $ip =~ /^([^:]+):/;
            $chazwazza = hex($chazwazza);

            push @ula, $ip if (($chazwazza & mask( 7, 16)) == 0xfc00);
            push @gua, $ip if (($chazwazza & mask( 3, 16)) == 0x2000);
            push @ll,  $ip if (($chazwazza & mask(10, 16)) == 0xfe80);
        }

        Dumper[@gua];
        Dumper[@ula];
        Dumper[@ll];
    }

    validate_ip(env("PIHOLE_IPV6_ADDRESS"));
    configure_pihole("IPV6_ADDRESS", 1, $env, "PIHOLE_IPV6_ADDRESS");
}

# Change an option in setupVars.conf
sub configure_pihole ($$$@) {
    return &configure($PIHOLE_CONF, @_);
}

sub configure_temperature ($) {
    my ($unit) = @_;
    validate("PIHOLE_TEMPERATURE_UNIT", 0, $unit, "k", "f", "c", "K", "F", "C");
    do_or_die("pihole", "-a", "-".lc($unit->val())) if $unit->exists();
}

sub configure_web_address ($$$) {
    my ($ipv4, $ipv6, $port) = @_;
    my $path = "/etc/lighttpd/lighttpd.conf";
    my @lighttpd = read_file($path);

    croak sprintf("%s (%s) is invalid, must be 1-65535", $port->name(), $port->val())
        unless ($port->val() =~ /\A\d+\z/ and $port->val() > 0 and $port->val() <= 65535);

    @lighttpd = grep {!/^\$SERVER\["socket"\]/} @lighttpd;
    @lighttpd = grep {!/^server\.port\s*=/} @lighttpd;
    @lighttpd = grep {!/^server\.bind\s*=/} @lighttpd;
    @lighttpd = grep {!/use-ipv6\.pl/} @lighttpd;

    push @lighttpd, "server.port = ".$port->val();
    push @lighttpd, 'server.use-ipv6 = "enable"' if $ipv6->exists();

    if ($ipv4->exists() and $ipv4->val() eq "0.0.0.0") {
        push @lighttpd, 'server.bind = "0.0.0.0"';
    } else {
        push @lighttpd, 'server.bind = "127.0.0.1"';
        push @lighttpd, sprintf('$SERVER["socket"] == "%s:%s" { }',   $ipv4->val(), $port->val()) if $ipv4->exists();
        push @lighttpd, sprintf('$SERVER["socket"] == "[%s]:%s" { }', $ipv6->val(), $port->val()) if $ipv6->exists();
    }

    write_file($path, @lighttpd);
}

sub configure_web_fastcgi ($$) {
    my ($ipv4, $host) = @_;
    my $path = "/etc/lighttpd/conf-enabled/15-fastcgi-php.conf";
    my @fastcgi = read_file($path);

    @fastcgi = grep {!/^\s*"PHP_ERROR_LOG"/ } @fastcgi;
    @fastcgi = grep {!/^\s*"VIRTUAL_HOST"/ } @fastcgi;
    @fastcgi = grep {!/^\s*"ServerIP"/ } @fastcgi;

    my @env;
    push @env, "\t\t\"bin-environment\" => (";
    push @env, sprintf('%s"VIRTUAL_HOST"  => "%s",', "\t\t\t", $host->val());
    push @env, sprintf('%s"ServerIP"      => "%s",', "\t\t\t", $ipv4->val()) if $ipv4->exists();
    push @env, sprintf('%s"PHP_ERROR_LOG" => "%s",', "\t\t\t", "/var/log/lighttpd/error.log");

    @fastcgi = sed {/"bin-environment"/} \@env, @fastcgi;
    write_file($path, @fastcgi);
}

sub configure_web_password ($$) {
    my ($pw, $pwfile) = @_;

    if ($pwfile->exists() and -f $pwfile->val() and -s $pwfile->val()) {
        say "Reading web password from ".$pwfile->val();
        $pw = lit(read_file($pwfile));
        chomp $pw;
    }

    if (!$pw->exists()) {
        $pw = lit(trim(`openssl rand -base64 20`));
        say "Generated new random web admin password: ".$pw->val();
    }

    do_or_die("pihole", "-a", "-p", $pw->val(), $pw->val());
}

# TODO this file isn't used (yet)
sub configure_whitelists () {
    my $path = "/etc/pihole/whitelists.list";
    return if -f $path;

    my @items = ();
    push @items, "https://github.com/anudeepND/whitelist/blob/master/domains/optional-list.txt";
    push @items, "https://github.com/anudeepND/whitelist/blob/master/domains/referral-sites.txt";
    push @items, "https://github.com/anudeepND/whitelist/blob/master/domains/whitelist.txt";
    write_file($path, join("\n", @items)."\n");
}

sub do_or_die (@) {
    say "+ ".join(" ", @_) if exists $ENV{"PIHOLE_DEBUG"};
    system(@_) and explain(@_);
}

# Explain how a call to system() failed, then abort
sub explain (@) {
    ($? == -1)  or croak join(" ", @_)." failed to execute: ".$!;
    ($? & 0x7f) or croak join(" ", @_)." died with signal ". ($? & 0x7f);
    croak join(" ", @_)." failed with exit code ".($? >> 8);
}

sub fix_capabilities ($) {
    my ($dns_user) = @_;
    my $ftl_path   = trim(`which pihole-FTL`);

    do_or_die("setcap", "CAP_SYS_NICE,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_ADMIN+ei", $ftl_path)
        if ($dns_user ne "root");
}

sub fix_permissions ($) {
    my $dns = $_[0]->val();
    my $www = "www-data";

    my @files = (
        {type=>"d", path=>"/etc/lighttpd",                uid=>"root", gid=>"root", mode=>"0755"},
        {type=>"d", path=>"/etc/pihole",                  uid=>$dns,   gid=>"root", mode=>"0755"}, # TODO
        {type=>"d", path=>"/var/cache/lighttpd/compress", uid=>$www,   gid=>"root", mode=>"0755"},
        {type=>"d", path=>"/var/cache/lighttpd/uploads",  uid=>$www,   gid=>"root", mode=>"0755"},
        {type=>"d", path=>"/var/log",                     uid=>"root", gid=>"root", mode=>"0755"},
        {type=>"d", path=>"/var/log/lighttpd",            uid=>$www,   gid=>"root", mode=>"0755"},
        {type=>"d", path=>"/var/log/pihole",              uid=>$dns,   gid=>"root", mode=>"0755"},
        {type=>"d", path=>"/run/lighttpd",                uid=>$www,   gid=>"root", mode=>"0755"},
        {type=>"d", path=>"/run/pihole",                  uid=>$dns,   gid=>"root", mode=>"0755"},
        {type=>"f", path=>"/etc/pihole/custom.list",      uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/etc/pihole/dhcp.leases",      uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/etc/pihole/dns-servers.conf", uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/etc/pihole/pihole-FTL.conf",  uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/etc/pihole/regex.list",       uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/etc/pihole/setupVars.conf",   uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/var/log/pihole.log",          uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/var/log/pihole-FTL.log",      uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/var/log/lighttpd/access.log", uid=>$www,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/var/log/lighttpd/error.log",  uid=>$www,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/run/pihole-FTL.pid",          uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/run/pihole-FTL.port",         uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"x", path=>"/run/pihole/FTL.sock"}
    );

    my %grouped = (
        touch => [],
        mkdir => [],
        rm    => [],
        uid   => {},
        gid   => {},
        mode  => {});

    foreach (@files) {
        push(@{$grouped{touch}}, $_->{path}) if ($_->{type} eq "f");
        push(@{$grouped{mkdir}}, $_->{path}) if ($_->{type} eq "d");
        push(@{$grouped{rm}},    $_->{path}) if ($_->{type} eq "x");

        if ($_->{type} ne "x") {
            $grouped{uid }{$_->{uid }} = () if !defined $grouped{uid }{$_->{uid }};
            $grouped{gid }{$_->{gid }} = () if !defined $grouped{gid }{$_->{gid }};
            $grouped{mode}{$_->{mode}} = () if !defined $grouped{mode}{$_->{mode}};

            push(@{$grouped{uid }{$_->{uid }}}, $_->{path});
            push(@{$grouped{gid }{$_->{gid }}}, $_->{path});
            push(@{$grouped{mode}{$_->{mode}}}, $_->{path});
        }
    }

    do_or_die("mkdir", "-p", @{$grouped{mkdir}}) if @{$grouped{mkdir}};
    do_or_die("touch",       @{$grouped{touch}}) if @{$grouped{touch}};
    do_or_die("rm", "-rf",   @{$grouped{rm}})    if @{$grouped{rm}};

    foreach $_ (keys %{$grouped{uid }}) { do_or_die("chown", $_, @{$grouped{uid }{$_}}); }
    foreach $_ (keys %{$grouped{gid }}) { do_or_die("chgrp", $_, @{$grouped{gid }{$_}}); }
    foreach $_ (keys %{$grouped{mode}}) { do_or_die("chmod", $_, @{$grouped{mode}{$_}}); }

    do_or_die("cp", "-f", "/etc/pihole/setupVars.conf", "/etc/pihole/setupVars.conf.bak");
}

sub mask ($$) {
    my ($bits, $size) = @_;
    return ((1 << $bits) - 1) << ($size - $bits);
}

sub print_env(\%) {
    my %env = %{$_[0]};

    say "Environment:";
    foreach my $k (sort (keys %env)) {
        printf "  %-50s= %s\n", $k, ($env{$k} // "undef");
    }
}

sub read_file ($) {
    my ($path)  = @_;

    if (!exists $FILES{$_[0]}) {
        @{$FILES{$path}} = do {
            local @ARGV = ($path);
            map { chomp; $_ } <>;
        }
    }

    return @{$FILES{$_[0]}}
}

sub sed (&$@) {
    my $test = shift;
    my $swap = shift;
    my @result;
    my $swappd;

    foreach $_ (@_) {
        if (&$test) {
            $swappd = (ref $swap eq "CODE") ? &$swap : $swap;

            given (ref $swappd) {
                when ("")       { push @result, $swappd;  }
                when ("ARRAY")  { push @result, @$swappd; }
                when ("SCALAR") { push @result, $$swappd; }
                default         { croak "wrong type"; }
            }
        } else {
            push @result, $_;
        }
    }

    return @result;
}

sub set_defaults (\%) {
    my ($env) = @_;

    $env->{"PIHOLE_ADMIN_EMAIL"                } //= "root\@example.com";
    $env->{"PIHOLE_DNS_BLOCKING_MODE"          } //= "NULL";
    $env->{"PIHOLE_DNS_BOGUS_PRIV"             } //= "true";
    $env->{"PIHOLE_DNS_DNSSEC"                 } //= "false";
    $env->{"PIHOLE_DNS_FQDN_REQUIRED"          } //= "true";
    $env->{"PIHOLE_DNS_LOG_QUERIES",           } //= "true";
    $env->{"PIHOLE_DNS_UPSTREAM_1"             } //= "1.1.1.1";
    $env->{"PIHOLE_DNS_USER"                   } //= "pihole";
    $env->{"PIHOLE_LISTEN"                     } //= "all";
    $env->{"PIHOLE_TEMPERATURE_UNIT"           } //= "f";
    $env->{"PIHOLE_WEB_ENABLED"                } //= "true";
    $env->{"PIHOLE_WEB_HOSTNAME"               } //= trim(`hostname -f 2>/dev/null || hostname`);
    $env->{"PIHOLE_WEB_INSTALL_SERVER"         } //= "true";
    $env->{"PIHOLE_WEB_INSTALL_UI"             } //= "true";
    $env->{"PIHOLE_WEB_PORT",                  } //= "80";
    $env->{"PIHOLE_WEB_UI"                     } //= "boxed";
}

sub test_configuration ($) {
    my ($dns_user) = @_;

    say "\n\n$PIHOLE_CONF";
    do_or_die("cat", "-n", $PIHOLE_CONF);

    say "\n\n$FTL_CONF";
    do_or_die("cat", "-n", $FTL_CONF);

    say "\n\n$DNSMASQ_CONF";
    do_or_die("cat", "-n", $DNSMASQ_CONF);

    say "\n\n/etc/dnsmasq.conf";
    do_or_die("cat", "-n", "/etc/dnsmasq.conf");

    say "\n\n/etc/lighttpd/lighttpd.conf";
    do_or_die("cat", "-n", "/etc/lighttpd/lighttpd.conf");

    say "\n\n/etc/lighttpd/conf-enabled/15-fastcgi-php.conf";
    do_or_die("cat", "-n", "/etc/lighttpd/conf-enabled/15-fastcgi-php.conf");

    # check lighttpd configuration
    do_or_die("lighttpd", "-t", "-f", "/etc/lighttpd/lighttpd.conf");

    # check pihole configuration
    do {
        local *STDOUT;
        my $output;
        open STDOUT, ">>", \$output;
        do_or_die("sudo", "-u", $dns_user->val(), "/usr/bin/pihole-FTL", "test");
    };
}

sub trim ($) {
    my ($str) = @_;
    $str =~ s/\A\s+|\s+\z//g if (defined $str);
    return $str;
}

# Enforce (non-)required and enumerated value constraints
sub validate ($$$@) {
    my $name  = shift;
    my $reqd  = shift;
    my $cvar  = shift;
    my %allow = map { $_ => 1 } @_;

    (!$cvar->exists() and $reqd) and
        croak(($cvar->name() // $name)." cannot be empty");

    ($cvar->exists() and %allow and !exists($allow{$cvar->val()})) and
        croak(($cvar->name() // $name)." cannot be ".$cvar->val()." (expected one of: ".join(", ", @_).")");
}

sub validate_ip ($) {
    my ($ip) = @_;

    return unless $ip->exists();
    system("ip", "route", "get", $ip->val()) and
        croak(sprintf("%s (%s) is invalid", $ip->name(), $ip->val()));
}

sub write_file ($@) {
    # my $path = shift;
    # @{$FILES{$path}} = @_;
}

sub sync_files() {
    foreach my $path (keys %FILES) {
        say "Writing $path";

        my ($io, $name) = tempfile();

        my $content = join "\n", @{$FILES{$path}};
        $content   .= "\n" unless $content =~ /\n\z/;

        print $io $content;
        close $io;
        rename $name, $path;
        delete $FILES{$path};
    }
}

###############################################################################

sub main {
    set_defaults(%ENV);
    configure_network(%ENV, env("PIHOLE_IPV4_ADDRESS"), env("PIHOLE_IPV6_ADDRESS"));
    print_env(%ENV);

    fix_capabilities(env("PIHOLE_DNS_USER"));
    fix_permissions(env("PIHOLE_DNS_USER"));

    # Update version numbers
    do_or_die("pihole", "updatechecker");

    configure_web_password(env("PIHOLE_WEB_PASSWORD"), env("PIHOLE_WEB_PASSWORD_FILE"));
    configure_web_address(env("PIHOLE_IPV4_ADDRESS"), env("PIHOLE_IPV6_ADDRESS"), env("PIHOLE_WEB_PORT"));
    configure_web_fastcgi(env("PIHOLE_IPV4_ADDRESS"), env("PIHOLE_WEB_HOSTNAME"));

    configure_dns_defaults();
    configure_dns_interface(env("PIHOLE_LISTEN"), env("PIHOLE_INTERFACE"));
    configure_dns_user(env("PIHOLE_DNS_USER"));
    configure_dns_hostname(env("PIHOLE_IPV4_ADDRESS"), env("PIHOLE_IPV6_ADDRESS"), env("PIHOLE_WEB_HOSTNAME"));
    configure_dns_fqdn(env("PIHOLE_DNS_FQDN_REQUIRED"));
    configure_dns_priv(env("PIHOLE_DNS_BOGUS_PRIV"));
    configure_dns_dnssec(env("PIHOLE_DNS_DNSSEC"));
    configure_dns_forwarding(
        env("PIHOLE_DNS_LAN_ENABLE"),
        env("PIHOLE_DNS_LAN_UPSTREAM"),
        env("PIHOLE_DNS_LAN_NETWORK"),
        env("PIHOLE_DNS_LAN_DOMAIN"));
    configure_dns_upstream(
        env("PIHOLE_DNS_UPSTREAM_1"),
        env("PIHOLE_DNS_UPSTREAM_2"),
        env("PIHOLE_DNS_UPSTREAM_3"),
        env("PIHOLE_DNS_UPSTREAM_4"));

    configure_temperature(env("PIHOLE_TEMPERATURE_UNIT"));
    configure_admin_email(env("PIHOLE_ADMIN_EMAIL"));

    configure_dhcp();

    configure_pihole("QUERY_LOGGING"                 , 0, env("PIHOLE_DNS_LOG_QUERIES"),   "true", "false");
    configure_pihole("INSTALL_WEB_SERVER"            , 0, env("PIHOLE_WEB_INSTALL_SERVER"),"true", "false");
    configure_pihole("INSTALL_WEB_INTERFACE"         , 0, env("PIHOLE_WEB_INSTALL_UI"),    "true", "false");
    configure_pihole("LIGHTTPD_ENABLED"              , 0, env("PIHOLE_WEB_ENABLED"),       "true", "false");
    configure_pihole("WEBUIBOXEDLAYOUT"              , 0, env("PIHOLE_WEB_UI"),            "boxed", "normal");

    # https://docs.pi-hole.net/ftldns/configfile/
    configure_ftl("BLOCKINGMODE",      1, env("PIHOLE_DNS_BLOCKING_MODE"),    "NULL", "IP-NODATA-AAAA", "IP", "NXDOMAIN", "NODATA");
    configure_ftl("SOCKET_LISTENING",  0, lit("local"),                       "local", "all");
    configure_ftl("FTLPORT",           0, lit("4711"));
    configure_ftl("RESOLVE_IPV6",      0, lit("true"),                        "true", "false");
    configure_ftl("RESOLVE_IPV4",      0, lit("true"),                        "true", "false");
    configure_ftl("DBIMPORT",          0, lit("true"),                        "true", "false");
    configure_ftl("MAXDBDAYS",         0, lit("180"));
    configure_ftl("DBINTERVAL",        0, lit("1.0"));
    #onfigure_ftl("PRIVACYLEVEL",      0, env("PIHOLE_DNS_PRIVACY_LVL"),      "0", "1", "2");
    #onfigure_ftl("CNAMEDEEPINSPECT",  1, env("PIHOLE_DNS_CNAME_INSPECT"),    "true", "false");
    #onfigure_ftl("IGNORE_LOCALHOST",  0, env("PIHOLE_DNS_IGNORE_LOCALHOST"), "true", "false");

    configure_blocklists();
    configure_whitelists();

    sync_files();
    test_configuration(env("PIHOLE_DNS_USER"));
}

###############################################################################

STDOUT->autoflush(1);
STDERR->autoflush(1);

main();
