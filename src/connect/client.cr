class CONNECT::Client < IO
  property outbound : IO
  getter dnsResolver : DNS::Resolver
  getter options : Options

  def initialize(@outbound : IO, @dnsResolver : DNS::Resolver, @options : Options)
  end

  def self.new(host : String, port : Int32, dns_resolver : DNS::Resolver, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new host: host, port: port, dns_resolver: dns_resolver, connect_timeout: timeout.connect

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, dnsResolver: dns_resolver, options: options
  end

  def self.new(ip_address : Socket::IPAddress, dns_resolver : DNS::Resolver, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new ip_address: ip_address, connect_timeout: timeout.connect

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, dnsResolver: dns_resolver, options: options
  end

  def authenticate_frame=(value : Frames::Authenticate)
    @authenticateFrame = value
  end

  def authenticate_frame
    @authenticateFrame
  end

  def authentication_method=(value : Frames::AuthenticationFlag)
    @authenticationMethod = value
  end

  def authentication_method
    @authenticationMethod ||= Frames::AuthenticationFlag::NoAuthentication
  end

  def read_timeout=(value : Int | Time::Span | Nil)
    _io = outbound
    _io.read_timeout = value if value if _io.responds_to? :read_timeout=
  end

  def read_timeout
    _io = outbound
    _io.read_timeout if _io.responds_to? :read_timeout
  end

  def write_timeout=(value : Int | Time::Span | Nil)
    _io = outbound
    _io.write_timeout = value if value if _io.responds_to? :write_timeout=
  end

  def write_timeout
    _io = outbound
    _io.write_timeout if _io.responds_to? :write_timeout
  end

  def outbound : IO
    @outbound
  end

  def local_address : Socket::Address?
    _io = outbound
    _io.responds_to?(:local_address) ? _io.local_address : nil
  end

  def remote_address : Socket::Address?
    _io = outbound
    _io.responds_to?(:remote_address) ? _io.remote_address : nil
  end

  def read(slice : Bytes) : Int32
    return 0_i32 if slice.empty?
    outbound.read slice
  end

  def write(slice : Bytes) : Nil
    return if slice.empty?
    outbound.write slice
  end

  def flush
    outbound.flush
  end

  def close
    outbound.close rescue nil
  end

  def closed?
    outbound.closed?
  end

  def establish!(host : String, port : Int32, remote_dns_resolution : Bool = true, user_agent : String? = nil)
    destination_address = Address.new host: host, port: port
    establish! destination_address: destination_address, remote_dns_resolution: remote_dns_resolution, user_agent: user_agent
  end

  def establish!(destination_address : Socket::IPAddress | Address, remote_dns_resolution : Bool = true, user_agent : String? = nil)
    case destination_address
    in Socket::IPAddress
    in Address
      CONNECT.to_ip_address(destination_address.host, destination_address.port).try { |ip_address| destination_address = ip_address }
    end

    unless remote_dns_resolution
      case destination_address
      in Socket::IPAddress
      in Address
        fetch_type, ip_addresses = dnsResolver.getaddrinfo host: destination_address.host, port: destination_address.port
        destination_address = ip_addresses.first
      end
    end

    case destination_address
    in Socket::IPAddress
      text_destination_address = String.build { |io| io << destination_address.address << ":" << destination_address.port }
    in Address
      text_destination_address = String.build { |io| io << destination_address.host << ":" << destination_address.port }
    end

    request = HTTP::Request.new method: "CONNECT", resource: text_destination_address, headers: HTTP::Headers.new, version: "HTTP/1.1"
    user_agent.try { |_user_agent| request["User-Agent"] = _user_agent }
    request.headers["Proxy-Connection"] = "Keep-Alive"
    request.headers["Host"] = text_destination_address

    case authentication_method
    in .no_authentication?
    in .basic?
      raise Exception.new String.build { |io| io << "Client.authenticate_frame is Nil!" } unless _authenticate_frame = authenticate_frame
      request.headers["Proxy-Authorization"] = proxy_authorization = String.build { |io| io << "Basic" << " " << Base64.strict_encode(String.build { |_io| _io << _authenticate_frame.userName << ":" << _authenticate_frame.password }) }
    end

    request.to_io io: outbound
    http_response = HTTP::Client::Response.from_io io: outbound, ignore_body: true, decompress: false
    return true if http_response.status.ok? && ("connection established" == http_response.status_message.try &.downcase)

    raise Exception.new String.build { |io| io << "Failed status received: " << "(Code: [" << http_response.status.to_i << "] | Message: [" << http_response.status_message << "])." }
  end
end
