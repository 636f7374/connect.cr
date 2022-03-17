struct CONNECT::Options
  property client : Client
  property server : Server
  property session : Session

  def initialize(@client : Client = Client.new, @server : Server = Server.new, @session : Session = Session.new)
  end

  struct Client
    property headers : HTTP::Headers
    property dataRaw : String?

    def initialize(@headers : HTTP::Headers = HTTP::Headers.new, @dataRaw : String? = nil)
    end
  end

  struct Server
    property maxRequestLineSize : Int32
    property maxHeadersSize : Int32

    def initialize
      @maxRequestLineSize = HTTP::MAX_REQUEST_LINE_SIZE
      @maxHeadersSize = HTTP::MAX_HEADERS_SIZE
    end
  end

  struct Session
    property aliveInterval : Time::Span
    property heartbeatInterval : Time::Span

    def initialize(@aliveInterval : Time::Span = 30_i32.seconds, @heartbeatInterval : Time::Span = 3_i32.seconds)
    end
  end
end
