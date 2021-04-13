class CONNECT::Server
  getter io : Socket::Server
  getter dnsResolver : DNS::Resolver?
  getter options : Options

  def initialize(@io : Socket::Server, @dnsResolver : DNS::Resolver?, @options : Options)
  end

  def local_address : Socket::Address?
    _io = io
    _io.responds_to?(:local_address) ? _io.local_address : nil
  end

  def remote_address : Socket::Address?
    _io = io
    _io.responds_to?(:remote_address) ? _io.remote_address : nil
  end

  def authorization=(value : Frames::AuthorizationFlag)
    @authorization = value
  end

  def authorization
    @authorization ||= Frames::AuthorizationFlag::NoAuthorization
  end

  def on_auth=(value : Proc(String?, String?, Frames::PermissionFlag))
    @onAuth = value
  end

  def on_auth
    @onAuth
  end

  def client_timeout=(value : TimeOut)
    @clientTimeOut = value
  end

  def client_timeout
    @clientTimeOut ||= TimeOut.new
  end

  def outbound_timeout=(value : TimeOut)
    @outboundTimeOut = value
  end

  def outbound_timeout
    @outboundTimeOut ||= TimeOut.new
  end

  def establish!(session : Session, start_immediately : Bool = true, sync_create_outbound_socket : Bool = true) : HTTP::Request
    # Check whether HTTP::Request can be obtained, and check it's Headers `Proxy-Authorization`.

    request = HTTP::Request.from_io io: session.inbound, max_request_line_size: options.server.maxRequestLineSize, max_headers_size: options.server.maxHeadersSize
    raise Exception.new String.build { |io| io << "Server.establish!: HTTP::Request.from_io type is not HTTP::Request (" << request.class << ")." } unless request.is_a? HTTP::Request

    return request unless start_immediately
    establish! session: session, request: request, start_immediately: start_immediately, sync_create_outbound_socket: sync_create_outbound_socket

    request
  end

  def establish!(session : Session, request : HTTP::Request, start_immediately : Bool = true, sync_create_outbound_socket : Bool = true) : HTTP::Request
    # Put Frames::Destination into Session.

    session.destination_frame = destination_frame = Frames::Destination.new request: request

    # Check (proxy_authorization, client_validity).

    session.check_authorization! server: self, request: request, response: nil
    check_client_validity! session: session, request: request

    # Put HTTP::Request and local_address, remote_address into Session.

    session_inbound = session.inbound
    session.local_address = session_inbound.responds_to?(:local_address) ? (session_inbound.local_address rescue nil) : nil
    session.remote_address = session_inbound.responds_to?(:remote_address) ? (session_inbound.remote_address rescue nil) : nil

    # Put tunnelMode into Frames::Destination.

    session.destination_frame.try do |destination_frame|
      destination_frame.tunnelMode = ("CONNECT" == request.method) ? true : false
      session.destination_frame = destination_frame
    end

    return request unless start_immediately
    establish! session: session, request: request, destination_frame: session.destination_frame, sync_create_outbound_socket: sync_create_outbound_socket

    request
  end

  def establish!(session : Session, request : HTTP::Request, destination_frame : CONNECT::Frames::Destination?, sync_create_outbound_socket : Bool = true) : Bool
    # If syncCreateOutboundSocket is true, then create Outbound socket.

    if sync_create_outbound_socket
      begin
        raise Exception.new "Server.establish!: Session.destination_frame is Nil!" unless destination_frame
      rescue ex
        response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: request.version, body_io: nil
        response.to_io io: session rescue nil

        raise ex
      end

      session.outbound = create_outbound_socket! session: session, request: request, destination_frame: destination_frame
    end

    destination_frame = session.destination_frame

    # If HTTP::Request.method is `CONNECT`, then check whether the established HTTP::Request is HTTPS.
    # ** Because MITM servers need accurate results. **
    # If it is not `CONNECT`, then merge the first HTTP::Request and Session.inbound into IO::Stapled.

    if "CONNECT" == request.method
      response = HTTP::Client::Response.new status_code: 200_i32, body: nil, status_message: "Connection established", version: request.version, body_io: nil
      response.to_io io: session

      uninitialized_buffer = uninitialized UInt8[4096_i32]
      read_length = session.read slice: uninitialized_buffer.to_slice

      pre_extract_memory = IO::Memory.new String.new uninitialized_buffer.to_slice[0_i32, read_length]
      pre_extract_request = HTTP::Request.from_io io: pre_extract_memory, max_request_line_size: options.server.maxRequestLineSize, max_headers_size: options.server.maxHeadersSize
      pre_extract_memory.rewind

      read_only_extract = Quirks::Extract.new partMemory: pre_extract_memory, wrapped: session.inbound
      session.inbound = stapled = IO::Stapled.new reader: read_only_extract, writer: session.inbound, sync_close: true

      traffic_type = pre_extract_request.is_a?(HTTP::Request) ? TrafficType::HTTP : TrafficType::HTTPS
      destination_frame.try &.trafficType = traffic_type
    else
      memory = IO::Memory.new
      request.to_io io: memory
      memory.rewind

      read_only_extract = Quirks::Extract.new partMemory: memory, wrapped: session.inbound
      session.inbound = stapled = IO::Stapled.new reader: read_only_extract, writer: session.inbound, sync_close: true
      destination_frame.try &.trafficType = TrafficType::HTTP
    end

    destination_frame.try { |_destination_frame| session.destination_frame = _destination_frame }

    true
  end

  private def create_outbound_socket!(session : Session, request : HTTP::Request, destination_frame : CONNECT::Frames::Destination) : TCPSocket
    begin
      destination_address = destination_frame.get_destination_address
    rescue ex
      response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: session rescue nil

      raise ex
    end

    begin
      case destination_address
      in Address
        raise Exception.new "Server.establish!: Server.dnsResolver is Nil!" unless dns_resolver = dnsResolver

        socket = TCPSocket.new host: destination_address.host, port: destination_address.port, dns_resolver: dns_resolver, connect_timeout: outbound_timeout.connect
        socket.read_timeout = outbound_timeout.read
        socket.write_timeout = outbound_timeout.write

        return socket
      in Socket::IPAddress
        socket = TCPSocket.new ip_address: destination_address, connect_timeout: outbound_timeout.connect
        socket.read_timeout = outbound_timeout.read
        socket.write_timeout = outbound_timeout.write

        return socket
      end
    rescue ex
      response = HTTP::Client::Response.new status_code: 504_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: session rescue nil

      raise ex
    end
  end

  private def check_client_validity!(session : Session, request : HTTP::Request) : Bool
    begin
      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers is empty!" } unless request_headers = request.headers
      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers lacks Host!" } unless headers_host = request_headers["Host"]?
      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers Host is empty!" } if headers_host.empty?
    rescue ex
      response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: session rescue nil

      raise ex
    end

    begin
      # Sometimes the destination information exists in Request.resource, sometimes it exists in Request.headers[Host].
      # We need to find them out, if not, set the default to port 80.

      host, delimiter, port = request.resource.rpartition ":"
      host, delimiter, port = headers_host.rpartition ":" unless port.to_i?
      host, port = Tuple.new port, "80" if host.empty? && delimiter.empty? && !port.size.zero?

      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers[Host] host or port is empty!" } if host.empty? || port.empty?
      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers[Host] port is non-Integer type!" } unless _port = port.to_i?
    rescue ex
      response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: session rescue nil

      raise ex
    end

    begin
      destination_address = CONNECT.to_ip_address host: host, port: _port rescue nil
      destination_frame = session.destination_frame

      if destination_address && destination_frame
        destination_frame.destinationIpAddress = destination_address

        case destination_address.family
        in .inet?
          destination_frame.addressType = Frames::AddressFlag::Ipv4
        in .inet6?
          destination_frame.addressType = Frames::AddressFlag::Ipv6
        in .unspec?
        in .unix?
        end

        session.destination_frame = destination_frame
      end

      destination_address = _destination_address = Address.new host: host, port: _port unless destination_address
      destination_frame = session.destination_frame

      if _destination_address && destination_frame
        destination_frame.destinationAddress = _destination_address
        destination_frame.addressType = Frames::AddressFlag::Domain
        session.destination_frame = destination_frame
      end

      check_destination_protection! destination_address: destination_address
    rescue ex
      response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: session rescue nil

      raise ex
    end

    request.headers.delete "Proxy-Connection"

    true
  end

  private def check_destination_protection!(destination_address : Address | Socket::IPAddress) : Bool
    return true unless destination_protection = options.server.destinationProtection

    case destination_address
    in Address
      to_ip_address = Socket::IPAddress.new address: destination_address.host, port: destination_address.port rescue nil
      destination_address = to_ip_address if to_ip_address
    in Socket::IPAddress
    end

    case destination_address
    in Address
      if destination_protection.addresses.find { |protection_address| (protection_address.host == destination_address.host) && (protection_address.port == destination_address.port) }
        raise Exception.new "Server.check_destination_protection!: Establish.destinationAddress is in your preset destinationProtection!"
      end
    in Socket::IPAddress
      server_local_address = io.local_address

      case server_local_address
      in Socket::UNIXAddress
      in Socket::IPAddress
        raise Exception.new "Server.check_destination_protection!: Establish.destinationAddress conflicts with your server address!" if InterfaceAddress.includes? ip_address: destination_address, interface_port: server_local_address.port
      in Socket::Address
      end

      raise Exception.new "Server.check_destination_protection!: Establish.destinationAddress is in your preset destinationProtection!" if destination_protection.ipAddresses.includes? destination_address
    end

    true
  end

  def accept? : Session?
    return unless socket = io.accept?
    socket.sync = true if socket.responds_to? :sync=

    client_timeout.try do |_timeout|
      socket.read_timeout = _timeout.read if socket.responds_to? :read_timeout=
      socket.write_timeout = _timeout.write if socket.responds_to? :write_timeout=
    end

    Session.new inbound: socket
  end
end

require "./quirks/*"
