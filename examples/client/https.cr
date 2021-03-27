require "../../src/connect.cr"

# Use `DNS.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# DNS.cr will send and receive DNS requests in concurrent.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocolType: DNS::ProtocolType::UDP
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), protocolType: DNS::ProtocolType::TLS
dns_resolver = DNS::Resolver.new dnsServers: dns_servers

# Create CONNECT::Options.

options = CONNECT::Options.new
options.client.alwaysUseTunnel = true

# `CONNECT::Client.new` will create a socket connected to the destination address.

client = CONNECT::Client.new host: "127.0.0.1", port: 1234_i32, dns_resolver: dns_resolver, timeout: CONNECT::TimeOut.new, options: options

# Then you can add Authentication Methods, such as `Basic`.

client.authentication_method = CONNECT::Frames::AuthenticationFlag::Basic
authenticate_frame = CONNECT::Frames::Authenticate.new authenticationType: CONNECT::Frames::AuthenticationFlag::Basic, userName: "admin", password: "abc123"
client.authenticate_frame = authenticate_frame

begin
  # Establish a Tunnel to example.com through outbound.

  client.establish! host: "www.example.com", port: 443_i32, remote_dns_resolution: false

  tls_context = OpenSSL::SSL::Context::Client.new
  tls_context.verify_mode = OpenSSL::SSL::VerifyMode::PEER

  tls_socket = OpenSSL::SSL::Socket::Client.new io: client.outbound, context: tls_context, sync_close: true, hostname: "www.example.com"
  tls_socket.sync = true if tls_socket.responds_to? :sync=
  client.outbound = tls_socket

  # Send HTTP::Request (Tunnel)
  http_request = HTTP::Request.new "GET", "/"
  http_request.headers.add "Host", "www.example.com:443"
  http_request.to_io io: client

  # Receive HTTP::Client::Response (Tunnel)
  http_response = HTTP::Client::Response.from_io io: client
  STDOUT.puts [Time.local, http_response]
rescue ex
  STDOUT.puts [ex]
end

# Never forget to close IO, otherwise it will cause socket leakage.

client.close
