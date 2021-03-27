require "../src/connect.cr"

# Use `DNS.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# DNS.cr will send and receive DNS requests in concurrent.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocolType: DNS::ProtocolType::UDP
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), protocolType: DNS::ProtocolType::TLS
dns_resolver = DNS::Resolver.new dnsServers: dns_servers

# `CONNECT::Options`, adjust the server policy.

options = CONNECT::Options.new

# Finally, you call `CONNECT::SessionProcessor.perform` to automatically process.
# This example is used to demonstrate how to use it, you can modify it as appropriate.

tcp_server = TCPServer.new host: "0.0.0.0", port: 1234_i32
server = CONNECT::Server.new io: tcp_server, dnsResolver: dns_resolver, options: options

server.client_timeout = CONNECT::TimeOut.new
server.outbound_timeout = CONNECT::TimeOut.new

# You can set `CONNECT::Server.authentication`, such as (`Basic` and CONNECT::Server.on_auth).

server.authentication = CONNECT::Frames::AuthenticationFlag::Basic
server.on_auth = ->(user_name : String?, password : String?) do
  return CONNECT::Frames::PermissionFlag::Denied unless _user_name = user_name
  return CONNECT::Frames::PermissionFlag::Denied if "admin" != _user_name

  return CONNECT::Frames::PermissionFlag::Denied unless _password = password
  return CONNECT::Frames::PermissionFlag::Denied if "abc123" != _password

  CONNECT::Frames::PermissionFlag::Passed
end

loop do
  session = server.accept? rescue nil
  next unless _session = session

  spawn do
    begin
      server.establish! session: _session, sync_create_outbound_socket: true
    rescue ex
      _session.cleanup rescue nil

      next
    end

    processor = CONNECT::SessionProcessor.new session: session
    processor.perform server: server
  end
end
