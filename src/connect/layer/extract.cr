module CONNECT::Layer
  class Extract < IO
    getter memory : IO::Memory
    getter wrapped : IO

    def initialize(@memory : IO::Memory, @wrapped : IO)
    end

    private def eof? : Bool
      memory.pos == memory.size
    end

    def write(slice : Bytes) : Nil
      raise Exception.new "CONNECT::Layer::Extract.write: Read-only IO, not writable!"
    end

    def read(slice : Bytes) : Int32
      return wrapped.read slice if memory.closed?

      length = memory.read slice
      memory.close if eof?

      length
    end

    def close
      wrapped.close
    end
  end
end
