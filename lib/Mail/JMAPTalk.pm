#!/usr/bin/perl -cw

use strict;
use warnings;

package Mail::JMAPTalk;

use HTTP::Tiny;
use JSON::XS qw(decode_json encode_json);
use Convert::Base64;
use File::LibMagic;
use Carp qw(confess);
use Data::Dumper;

our $VERSION = '0.03';
our $CLIENT = "Net-JMAPTalk";
our $AGENT = "$CLIENT/$VERSION";

sub new {
  my ($Proto, %Args) = @_;
  my $Class = ref($Proto) || $Proto;

  my $Self = bless { %Args }, $Class;

  return $Self;
}

sub ua {
  my $Self = shift;
  unless ($Self->{ua}) {
    $Self->{ua} = HTTP::Tiny->new(agent => $AGENT);
  }
  return $Self->{ua};
}

sub auth_header {
  my $Self = shift;
  return 'Basic ' . encode_base64("$Self->{user}:$Self->{password}", '');
}

sub uploaduri {
  my $Self = shift;
  my $scheme = $Self->{scheme} // 'http';
  my $host = $Self->{host} // 'localhost';
  my $port = $Self->{port} // ($scheme eq 'http' ? 80 : 443);
  my $url = $Self->{uploadurl} // '/upload';

  return $url if $url =~ m/^http/;

  return "$scheme://$host:$port$url";
}

sub uri {
  my $Self = shift;
  my $scheme = $Self->{scheme} // 'http';
  my $host = $Self->{host} // 'localhost';
  my $port = $Self->{port} // ($scheme eq 'http' ? 80 : 443);
  my $url = $Self->{url} // '/jmap';

  return $url if $url =~ m/^http/;

  return "$scheme://$host:$port$url";
}

sub Login {
  my ($Self, $Username, $Password) = @_;

  my $data = $Self->AuthRequest({
    username => $Username,
    clientName => $CLIENT,
    clientVersion => $VERSION,
    deviceName => $Self->{deviceName} || 'api',
  });

  while ($data->{continuationToken}) {
    die "Unknown method" unless grep { $_ eq 'password' } @{$data->{methods}};
    $data = $Self->Request({
      token => $data->{continuationToken},
      method => 'password',
      password => $Password,
    });
  }

  die "Failed to get a token" unless $data->{accessToken};

  $Self->{token} = $data->{accessToken};
  $Self->{url} = $data->{uri};
  $Self->{upload} = $data->{upload};
  $Self->{eventSource} = $data->{eventSource};

  return 1;
}

sub Request {
  my ($Self, $Requests, %Headers) = @_;

  $Headers{'Content-Type'} //= "application/json";

  if ($Self->{user}) {
    $Headers{'Authorization'} = $Self->auth_header();
  }
  if ($Self->{token}) {
    $Headers{'Authorization'} = "JMAP $Self->{token}";
  }

  my $uri = $Self->uri();

  my $Response = $Self->ua->post($uri, {
    headers => \%Headers,
    content => encode_json($Requests),
  });

  my $jdata;
  $jdata = eval { decode_json($Response->{content}) } if $Response->{success};

  if ($ENV{DEBUGJMAP}) {
    warn "JMAP " . Dumper($Requests, $Response);
  }

  # check your own success on the Response object
  if (wantarray) {
    return ($Response, $jdata);
  }

  confess "JMAP request for $Self->{user} failed ($uri): $Response->{status} $Response->{reason}: $Response->{content}"
    unless $Response->{success};

  confess "INVALID JSON $Response->{content}" unless $jdata;

  return $jdata;
}

sub _get_type {
  my $data = shift;
  # XXX - escape file names?
  my $magic = File::LibMagic->new();
  my $info = $magic->info_from_string($data);
  return $info->{mime_type};
}

sub Upload {
  my ($Self, $data, $type) = @_;

  my %Headers;
  $Headers{'Content-Type'} = $type || _get_type($data);

  if ($Self->{user}) {
    $Headers{'Authorization'} = $Self->auth_header();
  }
  if ($Self->{token}) {
    $Headers{'Authorization'} = "JMAP $Self->{token}";
  }

  my $uri = $Self->uploaduri();

  my $Response = $Self->ua->post($uri, {
    headers => \%Headers,
    content => $data,
  });

  my $jdata;
  $jdata = eval { decode_json($Response->{content}) } if $Response->{success};

  # check your own success on the Response object
  if (wantarray) {
    return ($Response, $jdata);
  }

  confess "JMAP request for $Self->{user} failed ($uri): $Response->{status} $Response->{reason}: $Response->{content}"
    unless $Response->{success};

  confess "INVALID JSON $Response->{content}" unless $jdata;

  return $jdata;
}


1;
__END__

=head1 NAME

Mail::JMAPTalk - Perl client for the http://jmap.io/ protocol

=head1 SYNOPSIS

    use Mail::JMAPTalk;

    my $Talk = Mail::JMAPTalk->new(url => $url);

    my $res = $jmap->Request([['setContacts', {
       create => {
           "#1" => {firstName => "first", lastName => "last"},
           "#2" => {firstName => "second", lastName => "last"},
       }}, "R1"]]);
    # [["contactsSet", {created => { "#1" => {...}, "#2" => {...} } }, "R1"]]

=head1 DESCRIPTION

This is a really basic wrapper around the JMAP protocol.  It has a
rudimentary "Login" command as well, but it doesn't support the
entire protocol yet.


=head1 SEE ALSO

http://jmap.io/ - protocol documentation and client guide.

=head1 AUTHOR

Bron Gondwana, E<lt>brong@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by FastMail Pty Ltd.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.20.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
