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

    sub is_defined {
        my $self = shift;
        return defined($self->val());
    }
}

###############################################################################

my $PIHOLE_CONF  = "/etc/pihole/setupVars.conf";
my $FTL_CONF     = "/etc/pihole/pihole-FTL.conf";
my $DNSMASQ_CONF = "/etc/dnsmasq.d/01-pihole.conf";

sub env ($;\%)  { return Cvar->env(@_); }
sub lit ($)     { return Cvar->lit(@_); }

sub configure ($$$$@);
sub configure_admin_email ($);
sub configure_blocklists ();
sub configure_dns_defaults;
sub configure_dns_hostname ($$@);
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

    write_file($path, join("\n", @conf)."\n");
    rename($PIHOLE_CONF.".new", $PIHOLE_CONF);
}

sub configure_admin_email ($) {
    my ($email) = @_;
    do_or_die("pihole", "-a", "-e", $email->val()) if $email->is_defined();
}

sub configure_blocklists () {
    my $path = "/etc/pihole/adlists.list";
    return if -f $path;

    my @items = ();
    push @items, "https://dbl.oisd.nl/\n";
    write_file($path, @items);
}

sub configure_dns_defaults {
    do_or_die("cp", "-f", "/etc/.pihole/advanced/01-pihole.conf", $DNSMASQ_CONF);
}

sub configure_dns_hostname ($$@) {
    my $ipv4 = shift;
    my $ipv6 = shift;
    my @names = @_;

    my @conf = read_file($DNSMASQ_CONF);
    # TODO

    write_file($DNSMASQ_CONF, @conf);
}

sub configure_dns_interface ($$) {
    my ($iface, $listen) = @_;

    my @conf = grep {!/^interface=/} read_file($DNSMASQ_CONF);
    push @conf, "interface=".$iface->val() if $iface->is_defined();

    write_file($DNSMASQ_CONF, @conf);
}

sub configure_dns_upstream ($@) {
    my @conf  = grep {!/^server=/} read_file($DNSMASQ_CONF);
    my $count = 0;

    foreach $_ (@_) {
        next unless $_->is_defined();

        # Need to remove optional port number
        # validate_ip($_);

        configure_pihole("PIHOLE_DNS_".(++$count), 0, $_->val());
        push @conf, "server=".$_->val();
        $count ++;
    }

    validate("PIHOLE_DNS_1", 1, $_[0]) if ($count == 1);
    write_file($DNSMASQ_CONF, @conf);
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

    if (!defined $ipv4) {
        explain("ip route get 1.1.1.1")
            unless (my $output = `ip route get 1.1.1.1`);

        my ($gw) = $output =~ m/via\s+([^\s]+)/;
        my ($if) = $output =~ m/dev\s+([^\s]+)/;
        my ($ip) = $output =~ m/src\s+([^\s]+)/;

        $env{"PIHOLE_IPV4_ADDRESS"} = $ip;
    }

    validate_ip(env("PIHOLE_IPV4_ADDRESS"));
    configure_pihole("IPV4_ADDRESS", 1, env("PIHOLE_IPV4_ADDRESS"));

    # TODO
    if (!defined $ipv6) {
        my $output = `ip route get 2606:4700:4700::1001 2>/dev/null`
            or return;

        my ($gw) = $output =~ m/via\s+([^\s]+)/;
        my ($if) = $output =~ m/dev\s+([^\s]+)/;
        my ($ip) = $output =~ m/src\s+([^\s]+)/;

        my @output = `ip -6 addr show dev $if`
            or explain("ip -6 addr show dev $if");

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

    # validate_ip(env("PIHOLE_IPV6_ADDRESS"));
    # configure_pihole("IPV6_ADDRESS", 1, $env, "PIHOLE_IPV6_ADDRESS");
}

# Change an option in setupVars.conf
sub configure_pihole ($$$@) {
    return &configure($PIHOLE_CONF, @_);
}

sub configure_temperature ($) {
    my ($unit) = @_;
    validate("PIHOLE_TEMPERATURE_UNIT", 0, $unit, "k", "f", "c", "K", "F", "C");
    do_or_die("pihole", "-a", "-".lc($unit->val())) if $unit->is_defined();
}

sub configure_web_address ($$$) {
    my ($ipv4, $ipv6, $port) = @_;
    my $path = "/etc/lighttpd/lighttpd.conf";
    my @conf = read_file($path);

    croak sprintf("%s (%s) is invalid, must be 1-65535", $port->name(), $port->val())
        unless ($port->val() =~ /^\d+$/ and $port->val() > 0 and $port->val() <= 65535);

    @conf = grep {!/^server.port\s*=/} @conf;
    push @conf, "server.port = ".$port->val();

    my @bind = ('server.bind = "127.0.0.1"');
    push @bind, sprintf('$SERVER["socket"] == "%s:%s" { }', $ipv4->val(), $port->val()) if $ipv4->is_defined();
    push @bind, sprintf('$SERVER["socket"] == "%s:%s" { }', $ipv6->val(), $port->val()) if $ipv6->is_defined();

    @conf = grep {!/^\$SERVER\["socket"/} @conf;
    @conf = grep {!/^server\.bind/} @conf;
    @conf = grep {!/use-ipv6\.pl/} @conf;
    push @conf, @bind;

    write_file($path, @conf);
}

sub configure_web_fastcgi ($$) {
    my ($ipv4, $host) = @_;
    my $path = "/etc/lighttpd/conf-enabled/15-fastcgi-php.conf";
    my @conf = read_file($path);

    @conf = grep {!/^\s*"PHP_ERROR_LOG"/ } @conf;
    @conf = grep {!/^\s*"VIRTUAL_HOST"/ } @conf;
    @conf = grep {!/^\s*"ServerIP"/ } @conf;

    my @env;
    push @env, "\t\t\"bin-environment\" => (";
    push @env, sprintf('"VIRTUAL_HOST"  => "%s"', $host->val());
    push @env, sprintf('"ServerIP"      => "%s"', $ipv4->val()) if $ipv4->is_defined();
    push @env, sprintf('"PHP_ERROR_LOG" => "%s"', "/var/log/lighttpd/error.log");

    @conf = sed {/"bin-environment"/} \@env, @conf;

    write_file($path, @conf);
}

sub configure_web_password ($$) {
    my ($pw, $pwfile) = @_;

    if ($pwfile->is_defined() and -f $pwfile->val() and -s $pwfile->val()) {
        say "Reading web password from ".$pwfile->val();
        $pw = lit(read_file($pwfile));
        chomp $pw;
    }

    if (!$pw->is_defined()) {
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
    explain(@_) if system(@_);
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
        {type=>"f", path=>"/var/log/lighttpd/access.log", uid=>$www,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/var/log/lighttpd/error.log",  uid=>$www,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/run/pihole-FTL.pid",          uid=>$dns,   gid=>"root", mode=>"0644"},
        {type=>"f", path=>"/run/pihole-FTL.port",         uid=>$dns,   gid=>"root", mode=>"0644"}
    );

    my @_files;
    do_or_die("mkdir", "-p",   @_files) if @_files = map $_->{path}, grep { $_->{type} eq "d"     } @files;
    do_or_die("touch",         @_files) if @_files = map $_->{path}, grep { $_->{type} eq "f"     } @files;
    do_or_die("chown", $dns,   @_files) if @_files = map $_->{path}, grep { $_->{uid} eq $dns     } @files;
    do_or_die("chown", $www,   @_files) if @_files = map $_->{path}, grep { $_->{uid} eq $www     } @files;
    do_or_die("chown", "root", @_files) if @_files = map $_->{path}, grep { $_->{uid} eq "root"   } @files;
    do_or_die("chgrp", $dns,   @_files) if @_files = map $_->{path}, grep { $_->{gid} eq $dns     } @files;
    do_or_die("chgrp", $www,   @_files) if @_files = map $_->{path}, grep { $_->{gid} eq $www     } @files;
    do_or_die("chown", "root", @_files) if @_files = map $_->{path}, grep { $_->{gid} eq "root"   } @files;
    do_or_die("chmod", "0755", @_files) if @_files = map $_->{path}, grep { $_->{mode} eq "0755"  } @files;
    do_or_die("chmod", "0644", @_files) if @_files = map $_->{path}, grep { $_->{mode} eq "0644"  } @files;

    do_or_die("rm", "-f", "/var/run/pihole/FTL.sock");
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
    local @ARGV = $_[0];
    return wantarray() ?
        map { chomp; $_ } <> :
        do  { local $/;   <> };
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

    $env->{"PIHOLE_BLOCKING_MODE"              } //= "NULL";
    $env->{"PIHOLE_TEMPERATURE_UNIT"           } //= "f";
    $env->{"PIHOLE_ADMIN_EMAIL"                } //= "root\@example.com";
    $env->{"PIHOLE_DNS_UPSTREAM_1"             } //= "1.1.1.1";
    $env->{"PIHOLE_LISTEN"                     } //= "all";
    $env->{"PIHOLE_QUERY_LOGGING"              } //= "true";
    $env->{"PIHOLE_DNS_BOGUS_PRIV"             } //= "true";
    $env->{"PIHOLE_DNS_FQDN_REQUIRED"          } //= "false";
    $env->{"PIHOLE_DNS_DNSSEC"                 } //= "false";
    $env->{"PIHOLE_DNS_CONDITIONAL_FORWARDING" } //= "false";
    $env->{"PIHOLE_WEB_HOSTNAME"               } //= trim(`hostname -f 2>/dev/null || hostname`);
    $env->{"PIHOLE_WEB_PORT",                  } //= "80";
    $env->{"PIHOLE_WEB_UI"                     } //= "boxed";
    $env->{"INSTALL_WEB_SERVER"                } //= "true";
    $env->{"INSTALL_WEB_INTERFACE"             } //= "true";
    $env->{"PIHOLE_LIGHTTPD_ENABLED"           } //= "true";
    $env->{"PIHOLE_DNS_USER"                   } //= "pihole";
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

    # check pihole configuration
    do {
        local *STDOUT;
        my $output;
        open STDOUT, ">>", \$output;
        do_or_die("sudo", "-u", $dns_user->val(), "-E", "/usr/bin/pihole-FTL", "test");
    };

    # check lighttpd configuration
    do_or_die("lighttpd", "-t", "-f", "/etc/lighttpd/lighttpd.conf");
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

    (!$cvar->is_defined() and $reqd) and
        croak(($cvar->name() // $name)." cannot be empty");

    ($cvar->is_defined() and %allow and !exists($allow{$cvar->val()})) and
        croak(($cvar->name() // $name)." cannot be ".$cvar->val()." (expected one of: ".join(", ", @_).")");
}

sub validate_ip ($) {
    my ($ip) = @_;

    if ($ip->is_defined() and system("ip route get '".$ip->val()."' 2>/dev/null")) {
        croak(sprintf("%s (%s) is invalid", $ip->name(), $ip->val()));
    }
}

sub write_file ($@) {
    my $path = shift;
    open(my $io, ">", $path) or croak "can't open $path for writing: $!";
    print $io join("\n", @_);
    print $io "\n" unless ($_[-1] =~ m/\n\z/);
    close $io;
}

###############################################################################

sub main {
    # https://github.com/pi-hole/pi-hole/blob/6b536b7428a1f57ff34ddc444ded6d3a62b00a38/automated%20install/basic-install.sh#L1474
    # installConfigs
    # TODO

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
    configure_dns_upstream(
        env("PIHOLE_DNS_UPSTREAM_1"),
        env("PIHOLE_DNS_UPSTREAM_2"),
        env("PIHOLE_DNS_UPSTREAM_3"),
        env("PIHOLE_DNS_UPSTREAM_4"));
    configure_dns_hostname(env("PIHOLE_IPV4_ADDRESS"), env("PIHOLE_IPV6_ADDRESS"), env("PIHOLE_WEB_HOSTNAME"));

    configure_temperature(env("PIHOLE_TEMPERATURE_UNIT"));
    configure_admin_email(env("PIHOLE_ADMIN_EMAIL"));

    configure_pihole("DNSMASQ_LISTENING"             , 0, env("PIHOLE_LISTEN"),            "all", "local", "iface");
    configure_pihole("PIHOLE_INTERFACE"              , 0, env("PIHOLE_INTERFACE"));
    configure_pihole("QUERY_LOGGING"                 , 0, env("PIHOLE_QUERY_LOGGING"),     "true", "false");
    configure_pihole("INSTALL_WEB_SERVER"            , 0, env("INSTALL_WEB_SERVER"),       "true", "false");
    configure_pihole("INSTALL_WEB_INTERFACE"         , 0, env("INSTALL_WEB_INTERFACE"),    "true", "false");
    configure_pihole("LIGHTTPD_ENABLED"              , 0, env("PIHOLE_LIGHTTPD_ENABLED"),  "true", "false");
    configure_pihole("DNS_BOGUS_PRIV"                , 0, env("PIHOLE_DNS_BOGUS_PRIV"),    "true", "false");
    configure_pihole("DNS_FQDN_REQUIRED"             , 0, env("PIHOLE_DNS_FQDN_REQUIRED"), "true", "false");
    configure_pihole("DNSSEC"                        , 0, env("PIHOLE_DNS_DNSSEC"),        "true", "false");
    configure_pihole("CONDITIONAL_FORWARDING"        , 0, env("PIHOLE_DNS_CONDITIONAL_FORWARDING"), "true", "false");
    configure_pihole("CONDITIONAL_FORWARDING_IP"     , 0, env("PIHOLE_DNS_CONDITIONAL_FORWARDING_IP"));
    configure_pihole("CONDITIONAL_FORWARDING_DOMAIN" , 0, env("PIHOLE_DNS_CONDITIONAL_FORWARDING_DOMAIN"));
    configure_pihole("CONDITIONAL_FORWARDING_REVERSE", 0, env("PIHOLE_DNS_CONDITIONAL_FORWARDING_REVERSE"));
    configure_pihole("WEBUIBOXEDLAYOUT"              , 0, env("PIHOLE_WEB_UI"),            "boxed", "normal");

    # https://docs.pi-hole.net/ftldns/configfile/
    configure_ftl("BLOCKINGMODE",      1, env("PIHOLE_BLOCKING_MODE"),        "NULL", "IP-NODATA-AAAA", "IP", "NXDOMAIN", "NODATA");
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

    # https://github.com/pi-hole/pi-hole/blob/e9b039139c468798fb6d9457e4c9012171faee33/advanced/Scripts/webpage.sh#L146
    #
    # ProcessDNSSettings
    #   PIHOLE_DNS_n
    #   DNS_FQDN_REQUIRED
    #   DNS_BOGUS_PRIV
    #   DNSSEC
    #   HOSTRECORD
    #   DNSMASQ_LISTENING
    #   CONDITIONAL_FORWARDING
    #   CONDITIONAL_FORWARDING_DOMAIN
    #   CONDITIONAL_FORWARDING_REVERSE
    #   CONDITIONAL_FORWARDING_IP
    #   REV_SERVER

    configure_blocklists();
    configure_whitelists();
    test_configuration(env("PIHOLE_DNS_USER"));
}

###############################################################################

main();
