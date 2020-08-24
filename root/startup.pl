#!/usr/bin/perl
use 5.010;
use strict;
use warnings;
no warnings "experimental";

use Carp qw(carp croak);
use Data::Dumper;
use File::Find;

my $PIHOLE_CONF  = "/etc/pihole/setupVars.conf";
my $FTL_CONF     = "/etc/pihole/pihole-FTL.conf";
my $DNSMASQ_CONF = "/etc/dnsmasq.d/01-pihole.conf";

sub main {
    # https://github.com/pi-hole/pi-hole/blob/6b536b7428a1f57ff34ddc444ded6d3a62b00a38/automated%20install/basic-install.sh#L1474
    # installConfigs

    validate("PIHOLE_DNS_USER", 1, \%ENV, "PIHOLE_DNS_USER");

    fix_capabilities($ENV{"PIHOLE_DNS_USER"});
    fix_permissions($ENV{"PIHOLE_DNS_USER"});

    set_defaults(\%ENV);
    configure_network(\%ENV);
    print_env(\%ENV);

    # Update version numbers
    do_or_die("pihole", "updatechecker");

    configure_web_address ($ENV{"PIHOLE_IPV4_ADDRESS"}, $ENV{"PIHOLE_IPV6_ADDRESS"}, $ENV{"PIHOLE_WEB_PORT"});
    configure_web_password($ENV{"PIHOLE_WEB_PASSWORD"}, $ENV{"PIHOLE_WEB_PASSWORD_FILE"});
    configure_web_fastcgi ($ENV{"PIHOLE_IPV4_ADDRESS"}, $ENV{"PIHOLE_WEB_HOSTNAME"});

    configure_dns_defaults();
    configure_dns_interface($ENV{"PIHOLE_INTERFACE"}, $ENV{"PIHOLE_LISTEN"});
    configure_dns_user     ($ENV{"PIHOLE_DNS_USER"});
    configure_dns_hostname ($ENV{"PIHOLE_IPV4_ADDRESS"}, $ENV{"PIHOLE_IPV6_ADDRESS"}, $ENV{"PIHOLE_WEB_HOSTNAME"});

    configure_temperature ($ENV{"PIHOLE_TEMPERATURE_UNIT"});
    configure_admin_email ($ENV{"PIHOLE_ADMIN_EMAIL"});

    configure_pihole("PIHOLE_DNS_1"                  , 1, \%ENV, "PIHOLE_DNS_UPSTREAM_1");
    configure_pihole("PIHOLE_DNS_2"                  , 0, \%ENV, "PIHOLE_DNS_UPSTREAM_2");
    configure_pihole("PIHOLE_DNS_3"                  , 0, \%ENV, "PIHOLE_DNS_UPSTREAM_3");
    configure_pihole("PIHOLE_DNS_4"                  , 0, \%ENV, "PIHOLE_DNS_UPSTREAM_4");
    configure_pihole("DNSMASQ_LISTENING"             , 0, \%ENV, "PIHOLE_LISTEN",            "all", "local", "iface");
    configure_pihole("PIHOLE_INTERFACE"              , 0, \%ENV, "PIHOLE_INTERFACE");
    configure_pihole("QUERY_LOGGING"                 , 0, \%ENV, "PIHOLE_QUERY_LOGGING",     "true", "false");
    configure_pihole("INSTALL_WEB_SERVER"            , 0, \%ENV, "INSTALL_WEB_SERVER",       "true", "false");
    configure_pihole("INSTALL_WEB_INTERFACE"         , 0, \%ENV, "INSTALL_WEB_INTERFACE",    "true", "false");
    configure_pihole("LIGHTTPD_ENABLED"              , 0, \%ENV, "PIHOLE_LIGHTTPD_ENABLED",  "true", "false");
    configure_pihole("DNS_BOGUS_PRIV"                , 0, \%ENV, "PIHOLE_DNS_BOGUS_PRIV",    "true", "false");
    configure_pihole("DNS_FQDN_REQUIRED"             , 0, \%ENV, "PIHOLE_DNS_FQDN_REQUIRED", "true", "false");
    configure_pihole("DNSSEC"                        , 0, \%ENV, "PIHOLE_DNS_DNSSEC",        "true", "false");
    configure_pihole("CONDITIONAL_FORWARDING"        , 0, \%ENV, "PIHOLE_DNS_CONDITIONAL_FORWARDING", "true", "false");
    configure_pihole("CONDITIONAL_FORWARDING_IP"     , 0, \%ENV, "PIHOLE_DNS_CONDITIONAL_FORWARDING_IP");
    configure_pihole("CONDITIONAL_FORWARDING_DOMAIN" , 0, \%ENV, "PIHOLE_DNS_CONDITIONAL_FORWARDING_DOMAIN");
    configure_pihole("CONDITIONAL_FORWARDING_REVERSE", 0, \%ENV, "PIHOLE_DNS_CONDITIONAL_FORWARDING_REVERSE");
    configure_pihole("WEBUIBOXEDLAYOUT"              , 0, \%ENV, "PIHOLE_WEB_UI",            "boxed", "normal");

    # https://docs.pi-hole.net/ftldns/configfile/
    configure_ftl("BLOCKINGMODE",      1, \%ENV, "PIHOLE_BLOCKING_MODE",        "NULL", "IP-NODATA-AAAA", "IP", "NXDOMAIN", "NODATA");
    #onfigure_ftl("PRIVACYLEVEL",      0, \%ENV, "PIHOLE_DNS_PRIVACY_LVL",      "0", "1", "2");
    #onfigure_ftl("CNAMEDEEPINSPECT",  1, \%ENV, "PIHOLE_DNS_CNAME_INSPECT",    "true", "false");
    #onfigure_ftl("IGNORE_LOCALHOST",  0, \%ENV, "PIHOLE_DNS_IGNORE_LOCALHOST", "true", "false");
    configure_ftl("SOCKET_LISTENING",  0, undef, "local",                       "local", "all");
    configure_ftl("FTLPORT",           0, undef, "4711");
    configure_ftl("RESOLVE_IPV6",      0, undef, "true",                        "true", "false");
    configure_ftl("RESOLVE_IPV4",      0, undef, "true",                        "true", "false");
    configure_ftl("DBIMPORT",          0, undef, "true",                        "true", "false");
    configure_ftl("MAXDBDAYS",         0, undef, "180");
    configure_ftl("DBINTERVAL",        0, undef, "1.0");

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
    check_configuration($ENV{"PIHOLE_DNS_USER"});
}

###############################################################################

sub fix_capabilities ($) {
    my ($dns_user) = @_;
    my $ftl_path   = trim(`which pihole-FTL`);

    do_or_die("setcap", "CAP_SYS_NICE,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_ADMIN+ei", $ftl_path)
        if ($dns_user ne "root");
}

sub fix_permissions ($) {
    my ($dns_user) = @_;

    # Re-apply perms from basic-install over any volume mounts that may be present (or not)
    do_or_die("mkdir", "-p",
      "/etc/pihole",
      "/var/run/pihole",
      "/var/log/pihole",
      "/var/log/lighttpd");
    do_or_die("chown", "www-data:root",
      "/etc/lighttpd",
      "/var/log/lighttpd");
    do_or_die("chown", "pihole:root",
      "/etc/pihole",
      "/var/run/pihole",
      "/var/log/pihole");
    do_or_die("chmod", "0755",
      "/etc/pihole",
      "/etc/lighttpd",
      "/var/run",
      "/var/log");

    do_or_die("touch",
      "/etc/pihole/setupVars.conf",
      "/var/log/lighttpd/access.log",
      "/var/log/lighttpd/error.log");
    do_or_die("chown", "www-data:root",
      "/var/log/lighttpd/access.log",
      "/var/log/lighttpd/error.log");

    my @files = (
      "/etc/pihole/custom.list",
      "/etc/pihole/dhcp.leases",
      "/etc/pihole/pihole-FTL.conf",
      "/etc/pihole/regex.list",
      "/etc/pihole/setupVars.conf",
      "/var/log/pihole",
      "/var/log/pihole-FTL.log",
      "/var/log/pihole.log",
      "/var/run/pihole-FTL.pid",
      "/var/run/pihole-FTL.port");

    do_or_die("touch", @files);
    do_or_die("chown", $dns_user.":root", @files);
    do_or_die("chmod", "0644",
      "/etc/pihole/pihole-FTL.conf",
      "/etc/pihole/regex.list",
      "/run/pihole-FTL.pid",
      "/run/pihole-FTL.port",
      "/var/log/pihole-FTL.log",
      "/var/log/pihole.log");

    do_or_die("rm", "-f",
      "/var/run/pihole/FTL.sock");

    do_or_die("cp", "-f",
        "/etc/pihole/setupVars.conf",
        "/etc/pihole/setupVars.conf.bak");
}

sub set_defaults (\%) {
    my ($env) = @_;

    $env->{"PIHOLE_BLOCKING_MODE"              } //= "NULL";
    $env->{"PIHOLE_TEMPERATURE_UNIT"           } //= "F";
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
}

sub print_env(\%) {
    my ($env) = @_;

    say "Environment:";
    foreach my $k (sort (keys %{$env})) { printf "  %-36s= %s\n", $k, ($env->{$k} // "undef"); }
}

sub configure_network (\%) {
    my ($env) = @_;

    if (!exists($env->{"PIHOLE_IPV4_ADDRESS"})) {
        explain("ip route get 1.1.1.1")
            unless (my $output = `ip route get 1.1.1.1`);

        my ($gw) = $output =~ m/via\s+([^\s]+)/;
        my ($if) = $output =~ m/dev\s+([^\s]+)/;
        my ($ip) = $output =~ m/src\s+([^\s]+)/;

        $env->{"PIHOLE_IPV4_ADDRESS"} = $ip;
    }

    validate_ip("PIHOLE_IPV4_ADDRESS", $env->{"PIHOLE_IPV4_ADDRESS"});
    configure_pihole("IPV4_ADDRESS", 1, $env, "PIHOLE_IPV4_ADDRESS");

    # TODO
    if (!exists($env->{"PIHOLE_IPV6_ADDRESS"})) {
        #xplain("ip route get 2606:4700:4700::1001")
        return
            unless (my $output = `ip route get 2606:4700:4700::1001 2>/dev/null`);

        my ($gw) = $output =~ m/via\s+([^\s]+)/;
        my ($if) = $output =~ m/dev\s+([^\s]+)/;
        my ($ip) = $output =~ m/src\s+([^\s]+)/;

        explain("ip -6 addr show dev $if")
            unless (my @output = `ip -6 addr show dev $if`);

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

    # validate_ip("PIHOLE_IPV6_ADDRESS", $env->{"PIHOLE_IPV6_ADDRESS"});
    # configure_pihole("IPV6_ADDRESS", 1, $env, "PIHOLE_IPV6_ADDRESS");
}

sub mask ($$$) {
    my ($bits, $size) = @_;
    return ((1 << $bits) - 1) << ($size - $bits);
}

sub validate_ip ($$) {
    my ($key, $ip) = @_;

    if ($ip and system("ip route get '".$ip."' 2>/dev/null")) {
        croak "$key ($ip) is invalid" unless ($? == 0);
    }
}

sub configure_web_address ($$$) {
    my ($ipv4, $ipv6, $port) = @_;
    my $path = "/etc/lighttpd/lighttpd.conf";
    my @conf = read_file($path);

    croak "PIHOLE_WEB_PORT $port is invalid, must be 1-65535"
        unless ($port =~ /^\d+$/ and $port > 0 and $port <= 65535);
    @conf = sed {/^server.port\s=/} "server.port = $port", @conf;

    my @bind = ('server.bind = "127.0.0.1"');
    push @bind, sprintf('$SERVER["socket"] == "%s:%s" { }', $ipv4, $port) if ($ipv4);
    push @bind, sprintf('$SERVER["socket"] == "%s:%s" { }', $ipv6, $port) if ($ipv6);

    @conf = grep {!/^\s*\$SERVER\["socket"/} @conf;
    @conf = sed {/^server\.bind\s*=/} \@bind, @conf;

    write_file($path, @conf);
}

sub configure_web_password ($$) {
    my ($pw, $pwfile) = @_;

    if ($pwfile and -f $pwfile and -s $pwfile) {
        say "Reading web password from $pwfile";
        $pw = read_file($pwfile);
        chomp $pw;
    }

    if (!$pw) {
        $pw = trim(`openssl rand -base64 20`);
        say "Generated new random web admin password: $pw";
    }

    do_or_die("pihole", "-a", "-p", $pw, $pw);
}

sub configure_web_fastcgi ($$) {
    my ($ipv4, $host) = @_;
    my $path = "/etc/lighttpd/conf-enabled/15-fastcgi-php.conf";
    my $conf = read_file($path); # TODO

    $conf =~ s/^\s*"VIRTUAL_HOST".*$//ms;
    $conf =~ s/^\s*"ServerIP".*$//ms;
    $conf =~ s/^\s*"PHP_ERROR_LOG".*$//ms;

    my $env;
    do {
        my @x = (sprintf('"VIRTUAL_HOST"  => "%s"', $host));
        push(@x, sprintf('"ServerIP"      => "%s"', $ipv4)) if $ipv4;
        push(@x, sprintf('"PHP_ERROR_LOG" => "%s"', "/var/log/lighttpd/error.log"));
        $env = join(",\n\t\t\t", @x);
    };

    $conf =~ s/^(\s*"bin-environment".*)$/$1\n\t\t\t$env\n/ms;

    write_file($path, $conf);
}

sub configure_temperature ($) {
    my ($unit) = @_;
    $unit = lc($unit) if $unit;
    validate("PIHOLE_TEMPERATURE_UNIT", 0, undef, $unit, "k", "f", "c");
    do_or_die("pihole", "-a", "-$unit")
        if $unit;
}

sub configure_admin_email ($) {
    my ($email) = @_;
    do_or_die("pihole", "-a", "-e", $email)
        if ($email);
}

sub configure_dns_defaults {
    do_or_die("cp", "/etc/.pihole/advanced/01-pihole.conf", "/etc/dnsmasq.d/");
    #if (!-f $DNSMASQ_CONF);
}

sub configure_dns_user ($) {
    my ($dns_user) = @_;
    configure("/etc/dnsmasq.conf", "user", 1, {PIHOLE_DNS_USER => $dns_user}, "PIHOLE_DNS_USER");

    find(sub {
        write_file($_, grep {!/^user=/} read_file($_)) if -f;
    }, "/etc/dnsmasq.d");
}

sub configure_dns_interface ($$) {
    my ($iface, $listen) = @_;

    my @cfg = read_file($DNSMASQ_CONF);
    #cfg = grep {!/^(#|\s*$)/}   @cfg;
    @cfg = grep {!/^interface=/} @cfg;

    # TODO

    write_file($DNSMASQ_CONF, @cfg);
}

sub configure_dns_hostname ($$@) {
    my $ipv4 = shift;
    my $ipv6 = shift;
    my @names = @_;

    my @cfg = read_file($DNSMASQ_CONF);
    #cfg = grep {!/^(#|\s*$)/} @cfg;
    @cfg = grep {!/^server=/}  @cfg;

    # TODO

    write_file($DNSMASQ_CONF, @cfg);
}

sub configure_blocklists () {
    my $path = "/etc/pihole/adlists.list";
    return if -f $path;

    my @items = ();
    push @items, "https://dbl.oisd.nl/\n";
    write_file($path, @items);
}

sub configure_whitelists () {
    my $path = "/etc/pihole/whitelists.list";
    return if -f $path;

    my @items = ();
    push @items, "https://github.com/anudeepND/whitelist/blob/master/domains/optional-list.txt";
    push @items, "https://github.com/anudeepND/whitelist/blob/master/domains/referral-sites.txt";
    push @items, "https://github.com/anudeepND/whitelist/blob/master/domains/whitelist.txt";
    write_file($path, join("\n", @items)."\n");
}

sub check_configuration ($) {
    my ($dns_user) = @_;

    say "\n\n$PIHOLE_CONF";
    do_or_die("cat", "-n", $PIHOLE_CONF);

    say "\n\n$FTL_CONF";
    do_or_die("cat", "-n", $FTL_CONF);

    say "\n\n$DNSMASQ_CONF";
    do_or_die("cat", "-n", $DNSMASQ_CONF);

    say "\n\n/etc/dnsmasq.conf";
    do_or_die("cat", "-n", "/etc/dnsmasq.conf");

    # check pihole configuration
    do {
        local *STDOUT;
        my $output;
        open STDOUT, ">>", \$output;
        do_or_die("sudo", "-u", $dns_user, "-E", "/usr/bin/pihole-FTL", "test");
    };

    # check lighttpd configuration
    do_or_die("sudo", "-u", "www-data", "-E", "lighttpd", "-t", "-f", "/etc/lighttpd/lighttpd.conf");
}

###############################################################################

sub trim ($) {
    my ($str) = @_;
    $str =~ s/\A\s+|\s+\z//g if (defined $str);
    return $str;
}

sub yesno($) {
    my ($b) = @_;
    return $b if (!defined $b or $b eq "");
    return (($b eq "true" or $b eq "yes" or $b eq "1") ? "yes" : "no");
}

# Change an option in setupVars.conf
sub configure_pihole ($$\%$@) {
    return configure($PIHOLE_CONF, @_);
}

sub configure_ftl ($$\%$@) {
    return configure($FTL_CONF, @_);
}

sub configure ($$$\%$@) {
    my $path = shift;
    validate(@_);

    my $val;
    my ($key, $req, $env, $lbl) = @_;

    if ($env and ref($env) eq "HASH") {
        $val = $env->{$lbl};
    } else {
        $val = $lbl;
        $lbl = $key;
    }

    my @cfg = grep {!/^$key=/} read_file($path);
    push @cfg, "$key=" . ($val // "");
    chomp @cfg;

    write_file($path, join("\n", @cfg)."\n");
    rename($PIHOLE_CONF.".new", $PIHOLE_CONF);
}

# Enforce (non-)required and enumerated value constraints
sub validate ($$\%$@) {
    my $key = shift;
    my $req = shift;
    my $env = shift;
    my $lbl = shift;
    my %set = map { $_ => 1 } @_;
    my $val;

    if ($env and ref($env) eq "HASH") {
        $val = $env->{$lbl};
    } else {
        $val = $lbl;
        $lbl = $key;
    }

    (!$val and $req) and
        croak "$lbl cannot be empty";

    ($val and %set and !exists($set{$val})) and
        croak "$lbl cannot be $val (expected one of: ".join(", ", keys %set).")";
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

sub read_file ($) {
    local @ARGV = $_[0];
    return wantarray() ?
        map { chomp; $_ } <> :
        do  { local $/;   <> };
}

sub write_file ($@) {
    my $path = shift;
    open(my $io, ">", $path) or croak "can't open $path for writing: $!";
    print $io join("\n", @_);
    print $io "\n" unless ($_[-1] =~ m/\n\z/);
    close $io;
}

sub sed (&$@) {
    my $test = shift;
    my $swap = shift;
    my @result;
    my $swappd;

    foreach $_ (@_) {
        if (&$test) {
            $swappd = (ref $swap == "CODE") ? &$swap : $swap;

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

###############################################################################

main();
say "startup.pl finished";
