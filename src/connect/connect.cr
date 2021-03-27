module CONNECT
  enum ARType : UInt8
    Ask   = 0_u8
    Reply = 1_u8
  end

  enum TrafficType : UInt8
    HTTP  = 0_u8
    HTTPS = 1_u8
  end

  def self.to_ip_address(host : String, port : Int32)
    Socket::IPAddress.new host, port rescue nil
  end
end
