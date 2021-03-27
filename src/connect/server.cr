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

  def authentication=(value : Frames::AuthenticationFlag)
    @authentication = value
  end

  def authentication
    @authentication ||= Frames::AuthenticationFlag::NoAuthentication
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

  def establish!(session : Session, sync_create_outbound_socket : Bool = true) : Bool
    # Check whether HTTP::Request can be obtained, and check it's Headers `Proxy-Authorization`.

    http_request = HTTP::Request.from_io io: session, max_request_line_size: options.server.maxRequestLineSize, max_headers_size: options.server.maxHeadersSize
    raise Exception.new String.build { |io| io << "Server.establish!: HTTP::Request.from_io type is not HTTP::Request (" << http_request.class << ")." } unless http_request.is_a? HTTP::Request
    session.destination_frame = Frames::Destination.new request: http_request

    # Check (proxy_authorization, client_validity).

    check_proxy_authorization! session: session, http_request: http_request
    check_client_validity! session: session, http_request: http_request

    # Put HTTP::Request and local_address, remote_address into Session.

    session_inbound = session.inbound
    session.local_address = session_inbound.responds_to?(:local_address) ? (session_inbound.local_address rescue nil) : nil
    session.remote_address = session_inbound.responds_to?(:remote_address) ? (session_inbound.remote_address rescue nil) : nil

    # If syncCreateOutboundSocket is true, then create Outbound socket.

    session.outbound = create_outbound_socket!(session: session, http_request: http_request) if sync_create_outbound_socket
    destination_frame = session.destination_frame

    # If HTTP::Request.method is `CONNECT`, then check whether the established HTTP::Request is HTTPS.
    # ** Because MITM servers need accurate results. **
    # If it is not `CONNECT`, then merge the first HTTP::Request and Session.inbound into IO::Stapled.

    if "CONNECT" == http_request.method
      http_client_response = HTTP::Client::Response.new status_code: 200_i32, body: nil, status_message: "Connection established", version: http_request.version, body_io: nil
      http_client_response.to_io io: session

      uninitialized_buffer = uninitialized UInt8[4096_i32]
      read_length = session.read slice: uninitialized_buffer.to_slice

      pre_extract_memory = IO::Memory.new String.new uninitialized_buffer.to_slice[0_i32, read_length]
      pre_extract_http_request = HTTP::Request.from_io io: pre_extract_memory, max_request_line_size: options.server.maxRequestLineSize, max_headers_size: options.server.maxHeadersSize
      pre_extract_memory.rewind

      read_only_extract = Quirks::Extract.new partMemory: pre_extract_memory, wrapped: session.inbound
      session.inbound = stapled = IO::Stapled.new reader: read_only_extract, writer: session.inbound, sync_close: true

      if destination_frame
        destination_frame.tunnelMode = true
        traffic_type = pre_extract_http_request.is_a?(HTTP::Request) ? TrafficType::HTTP : TrafficType::HTTPS
        destination_frame.trafficType = traffic_type
      end
    else
      memory = IO::Memory.new
      http_request.to_io io: memory
      memory.rewind

      read_only_extract = Quirks::Extract.new partMemory: memory, wrapped: session.inbound
      session.inbound = stapled = IO::Stapled.new reader: read_only_extract, writer: session.inbound, sync_close: true

      if destination_frame
        destination_frame.tunnelMode = false
        destination_frame.trafficType = TrafficType::HTTP
      end
    end

    destination_frame.try { |_destination_frame| session.destination_frame = _destination_frame }

    true
  end

  private def create_outbound_socket!(session : Session, http_request : HTTP::Request) : TCPSocket
    begin
      raise Exception.new "Server.establish!: Session.destination_frame is Nil!" unless destination_frame = session.destination_frame
      destination_address = destination_frame.get_destination_address
    rescue ex
      http_client_response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: http_request.version, body_io: nil
      http_client_response.to_io io: session

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
      http_client_response = HTTP::Client::Response.new status_code: 504_i32, body: nil, version: http_request.version, body_io: nil
      http_client_response.to_io io: session

      raise ex
    end
  end

  private def check_proxy_authorization!(session : Session, http_request : HTTP::Request)
    case authentication
    in .no_authentication?
    in .basic?
      check_basic_proxy_authorization! session: session, http_request: http_request
      http_request.headers.delete "Proxy-Authorization"
    end
  end

  private def check_basic_proxy_authorization!(session : Session, http_request : HTTP::Request) : Bool
    begin
      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers is empty!" } unless http_request_headers = http_request.headers
      headers_proxy_authorization = http_request_headers["Proxy-Authorization"]?

      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers lacks [Proxy-Authorization]!" } unless headers_proxy_authorization
      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] is empty!" } if headers_proxy_authorization.empty?
    rescue ex
      http_client_response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: http_request.version, body_io: nil
      http_client_response.to_io io: session

      raise ex
    end

    begin
      authentication_type, delimiter, base64_user_name_password = headers_proxy_authorization.rpartition " "
      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] authenticationType or base64UserNamePassword is empty!" } if authentication_type.empty? || base64_user_name_password.empty?
      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] type is not UserNamePassword! (" << authentication_type << ")" } if "Basic" != authentication_type

      decoded_base64_user_name_password = Base64.decode_string base64_user_name_password rescue nil
      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] Base64 decoding failed!" } unless decoded_base64_user_name_password

      user_name, delimiter, password = decoded_base64_user_name_password.rpartition ":"
      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] username or password is empty!" } if user_name.empty? || password.empty?

      permission_type = on_auth.try &.call(user_name, password) || Frames::PermissionFlag::Passed
      raise Exception.new String.build { |io| io << "Server.check_basic_proxy_authorization!: Your server expects AuthenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] onAuth callback returns Denied!" } if permission_type.denied?
    rescue ex
      http_client_response = HTTP::Client::Response.new status_code: 401_i32, body: nil, version: http_request.version, body_io: nil
      http_client_response.to_io io: session

      raise ex
    end

    session.authenticate_frame = Frames::Authenticate.new authenticationType: Frames::AuthenticationFlag::Basic, userName: user_name, password: password

    true
  end

  private def check_client_validity!(session : Session, http_request : HTTP::Request)
    begin
      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers is empty!" } unless http_request_headers = http_request.headers
      headers_host = http_request_headers["Host"]?

      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers lacks Host!" } unless headers_host
      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers Host is empty!" } if headers_host.empty?
    rescue ex
      http_client_response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: http_request.version, body_io: nil
      http_client_response.to_io io: session

      raise ex
    end

    begin
      host, delimiter, port = headers_host.rpartition ":"

      # If HTTP::Request.method is not CONNECT, We need to swap host and port and set Default port to 80.

      unless "CONNECT" == http_request.method
        host = port if host.empty?
        port = "80" if host == port unless port.empty?
      end

      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers[Host] host or port is empty!" } if host.empty? || port.empty?
      raise Exception.new String.build { |io| io << "Server.check_client_validity!: Client HTTP::Headers[Host] port is non-Integer type!" } unless _port = port.to_i?
    rescue ex
      http_client_response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: http_request.version, body_io: nil
      http_client_response.to_io io: session

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
      http_client_response = HTTP::Client::Response.new status_code: 406_i32, body: nil, version: http_request.version, body_io: nil
      http_client_response.to_io io: session

      raise ex
    end

    http_request.headers.delete "Proxy-Connection"
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
