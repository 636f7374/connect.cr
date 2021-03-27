struct CONNECT::Options
  property client : Client
  property server : Server

  def initialize(@client : Client = Client.new, @server : Server = Server.new)
  end

  struct Client
    property alwaysUseTunnel : Bool

    def initialize
      @alwaysUseTunnel = true
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
