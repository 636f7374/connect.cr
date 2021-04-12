abstract struct CONNECT::Frames
  Base64AuthorizationMapping = Set{['+', '!'], ['/', '%'], ['=', '#'], ['.', '$'], ['_', '&']}

  enum AuthorizationFlag : UInt8
    NoAuthorization = 0_u8
    Basic           = 1_u8
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

  def self.encode_sec_websocket_protocol_authorization(user_name : String, password : String) : String
    authorization = Base64.strict_encode String.build { |_io| _io << user_name << ':' << password }
    Base64AuthorizationMapping.each { |chars| authorization = authorization.gsub chars.first, chars.last }

    authorization
  end

  def self.decode_sec_websocket_protocol_authorization!(authorization : String) : String
    Base64AuthorizationMapping.each { |chars| authorization = authorization.gsub chars.last, chars.first }
    Base64.decode_string authorization
  end
end

require "./frames/*"
