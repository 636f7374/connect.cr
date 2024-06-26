class CONNECT::Client < IO
  property outbound : IO
  getter options : Options

  def initialize(@outbound : IO, @options : Options)
  end

  def self.new(host : String, port : Int32, dns_resolver : DNS::Resolver, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new host: host, port: port, dns_resolver: dns_resolver, connect_timeout: timeout.connect, caller: nil

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, options: options
  end

  def self.new(ip_address : Socket::IPAddress, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new ip_address: ip_address, connect_timeout: timeout.connect

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, options: options
  end

  def authorize_frame=(value : Frames::Authorize)
    @authorizeFrame = value
  end

  def authorize_frame
    @authorizeFrame
  end

  def read_timeout=(value : Int | Time::Span | Nil)
    _io = @outbound
    _io.read_timeout = value if value if _io.responds_to? :read_timeout=
  end

  def read_timeout
    _io = @outbound
    _io.read_timeout if _io.responds_to? :read_timeout
  end

  def write_timeout=(value : Int | Time::Span | Nil)
    _io = @outbound
    _io.write_timeout = value if value if _io.responds_to? :write_timeout=
  end

  def write_timeout
    _io = @outbound
    _io.write_timeout if _io.responds_to? :write_timeout
  end

  def local_address : Socket::Address?
    _io = @outbound
    _io.responds_to?(:local_address) ? _io.local_address : nil
  end

  def remote_address : Socket::Address?
    _io = @outbound
    _io.responds_to?(:remote_address) ? _io.remote_address : nil
  end

  def read(slice : Bytes) : Int32
    return 0_i32 if slice.empty?
    @outbound.read slice: slice
  end

  def write(slice : Bytes) : Nil
    return if slice.empty?
    @outbound.write slice: slice
  end

  def flush
    @outbound.flush
  end

  def close
    @outbound.close rescue nil
  end

  def closed?
    @outbound.closed?
  end

  def establish!(dns_resolver : DNS::Resolver, host : String, port : Int32, remote_dns_resolution : Bool = true, headers : HTTP::Headers = options.client.headers, data_raw : String? = options.client.dataRaw)
    destination_address = Address.new host: host, port: port
    establish! dns_resolver: dns_resolver, destination_address: destination_address, remote_dns_resolution: remote_dns_resolution, headers: headers, data_raw: data_raw
  end

  def establish!(dns_resolver : DNS::Resolver, destination_address : Socket::IPAddress | Address, remote_dns_resolution : Bool = true, headers : HTTP::Headers = options.client.headers, data_raw : String? = options.client.data_raw)
    Client.establish! outbound: outbound, destination_address: destination_address, dns_resolver: dns_resolver, authorize_frame: authorize_frame, remote_dns_resolution: remote_dns_resolution, headers: headers, data_raw: data_raw
  end

  def self.establish!(outbound : IO, destination_address : Socket::IPAddress | Address, dns_resolver : DNS::Resolver?, authorize_frame : Frames::Authorize? = nil, remote_dns_resolution : Bool = true, headers : HTTP::Headers = HTTP::Headers.new, data_raw : String? = nil)
    case destination_address
    in Socket::IPAddress
    in Address
      CONNECT.to_ip_address(destination_address.host, destination_address.port).try { |ip_address| destination_address = ip_address }
    end

    unless remote_dns_resolution
      case destination_address
      in Socket::IPAddress
      in Address
        raise Exception.new String.build { |io| io << "Client.establish!: dns_resolver is Nil!" } unless dns_resolver
        delegator, fetch_type, ip_addresses = dns_resolver.getaddrinfo host: destination_address.host, port: destination_address.port
        destination_address = ip_addresses.first
      end
    end

    case destination_address
    in Socket::IPAddress
      text_destination_address = String.build { |io| io << destination_address.address << ':' << destination_address.port }
    in Address
      text_destination_address = String.build { |io| io << destination_address.host << ':' << destination_address.port }
    end

    request = HTTP::Request.new method: "CONNECT", resource: text_destination_address, headers: headers, body: data_raw, version: "HTTP/1.1"
    request.headers["Proxy-Connection"] = "Keep-Alive"
    request.headers["Host"] = headers["Host"]? || text_destination_address

    if authorize_frame
      case authorize_frame.authorizationType
      in .no_authorization?
      in .basic?
        request.headers["Proxy-Authorization"] = proxy_authorization = String.build { |io| io << "Basic" << ' ' << Base64.strict_encode(String.build { |_io| _io << authorize_frame.userName << ':' << authorize_frame.password }) }
      end
    end

    request.to_io io: outbound
    response = HTTP::Client::Response.from_io io: outbound, ignore_body: true, decompress: false

    case response.version
    when "HTTP/1.0"
      return true if response.status.ok?
    when "HTTP/1.1"
      return true if response.status.ok? && ("connection established" == response.status_message.try &.downcase)
    end

    raise Exception.new String.build { |io| io << "Client.establish!: Failed status received: " << "(Code: [" << response.status.to_i << "] | Message: [" << response.status_message << "])." }
  end
end
