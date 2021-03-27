abstract struct CONNECT::Frames
  enum AuthenticationFlag : UInt8
    NoAuthentication = 0_u8
    Basic            = 1_u8
  end

  enum AddressFlag : UInt8
    Ipv4   = 1_u8
    Domain = 3_u8
    Ipv6   = 4_u8
  end

  enum PermissionFlag : UInt8
    Passed = 0_u8
    Denied = 1_u8
  end
end

require "./frames/*"
