class CONNECT::Session < IO
  property inbound : IO
  property outbound : IO?
  property syncCloseOutbound : Bool

  def initialize(@inbound : IO)
    @outbound = nil
    @syncCloseOutbound = true
  end

  def read_timeout=(value : Int | Time::Span | Nil)
    _io = inbound
    _io.read_timeout = value if value if _io.responds_to? :read_timeout=
  end

  def read_timeout
    _io = inbound
    _io.read_timeout if _io.responds_to? :read_timeout
  end

  def write_timeout=(value : Int | Time::Span | Nil)
    _io = inbound
    _io.write_timeout = value if value if _io.responds_to? :write_timeout=
  end

  def write_timeout
    _io = inbound
    _io.write_timeout if _io.responds_to? :write_timeout
  end

  def local_address=(value : Socket::Address?)
    @localAddress = value
  end

  def local_address : Socket::Address?
    @localAddress
  end

  def remote_address=(value : Socket::Address?)
    @remoteAddress = value
  end

  def remote_address : Socket::Address?
    @remoteAddress
  end

  def authenticate_frame=(value : Frames::Authenticate)
    @authenticateFrame = value
  end

  def authenticate_frame
    @authenticateFrame
  end

  def destination_frame=(value : Frames::Destination)
    @destinationFrame = value
  end

  def destination_frame
    @destinationFrame
  end

  def source_tls_socket=(value : OpenSSL::SSL::Socket::Server)
    @sourceTlsSocket = value
  end

  def source_tls_socket
    @sourceTlsSocket
  end

  def source_tls_context=(value : OpenSSL::SSL::Context::Server)
    @sourceTlsContext = value
  end

  def source_tls_context
    @sourceTlsContext
  end

  def destination_tls_socket=(value : OpenSSL::SSL::Socket::Client)
    @destinationTlsSocket = value
  end

  def destination_tls_socket
    @destinationTlsSocket
  end

  def destination_tls_context=(value : OpenSSL::SSL::Context::Client)
    @destinationTlsContext = value
  end

  def destination_tls_context
    @destinationTlsContext
  end

  def read(slice : Bytes) : Int32
    return 0_i32 if slice.empty?
    inbound.read slice
  end

  def write(slice : Bytes) : Nil
    return if slice.empty?
    inbound.write slice
  end

  def close
    inbound.close rescue nil

    if syncCloseOutbound
      outbound.try &.close rescue nil
    end

    true
  end

  def cleanup : Bool
    close
    free_tls!
    reset reset_tls: true

    true
  end

  private def free_tls!
    source_tls_socket.try &.skip_finalize = true
    source_tls_socket.try &.free

    source_tls_context.try &.skip_finalize = true
    source_tls_context.try &.free

    destination_tls_socket.try &.skip_finalize = true
    destination_tls_socket.try &.free

    destination_tls_context.try &.skip_finalize = true
    destination_tls_context.try &.free
  end

  def set_transfer_tls(transfer : Transfer, reset : Bool)
    _source_tls_socket = source_tls_socket
    transfer.source_tls_socket = _source_tls_socket if _source_tls_socket
    _source_tls_context = source_tls_context
    transfer.source_tls_context = _source_tls_context if _source_tls_context

    _destination_tls_socket = destination_tls_socket
    transfer.destination_tls_socket = _destination_tls_socket if _destination_tls_socket
    _destination_tls_context = destination_tls_context
    transfer.destination_tls_context = _destination_tls_context if _destination_tls_context

    if reset
      @sourceTlsSocket = nil
      @sourceTlsContext = nil
      @destinationTlsSocket = nil
      @destinationTlsContext = nil
    end
  end

  def reset(reset_tls : Bool)
    closed_memory = IO::Memory.new 0_i32
    closed_memory.close

    @inbound = closed_memory
    @outbound = closed_memory

    if reset_tls
      @sourceTlsSocket = nil
      @sourceTlsContext = nil
      @destinationTlsSocket = nil
      @destinationTlsContext = nil
    end
  end

  def closed?
    inbound.closed?
  end
end
