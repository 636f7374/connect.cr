struct CONNECT::Options
  property connectionPool : ConnectionPool
  property client : Client
  property server : Server

  def initialize(@connectionPool : ConnectionPool = ConnectionPool.new, @client : Client = Client.new, @server : Server = Server.new)
  end

  struct ConnectionPool
    property clearInterval : Time::Span
    property capacity : Int32

    def initialize(@clearInterval : Time::Span = 10_i32.seconds, @capacity : Int32 = 5_i32)
    end
  end

  struct Client
    property headers : HTTP::Headers
    property dataRaw : String?

    def initialize(@headers : HTTP::Headers = HTTP::Headers.new, @dataRaw : String? = nil)
    end
  end

  struct Server
    property destinationProtection : DestinationProtection?
    property maxRequestLineSize : Int32
    property maxHeadersSize : Int32

    def initialize
      @destinationProtection = DestinationProtection.new
      @maxRequestLineSize = HTTP::MAX_REQUEST_LINE_SIZE
      @maxHeadersSize = HTTP::MAX_HEADERS_SIZE
    end

    struct DestinationProtection
      property addresses : Set(Address)
      property ipAddresses : Set(Socket::IPAddress)

      def initialize
        @addresses = Set(Address).new
        @ipAddresses = Set(Socket::IPAddress).new
      end
    end
  end
end
