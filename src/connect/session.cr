class CONNECT::Session
  property source : IO
  getter options : Options
  property destination : IO?

  def initialize(@source : IO, @options : Options)
    @destination = nil
  end

  def authorize_frame=(value : Frames::Authorize)
    @authorizeFrame = value
  end

  def authorize_frame
    @authorizeFrame
  end

  def destination_frame=(value : Frames::Destination)
    @destinationFrame = value
  end

  def destination_frame
    @destinationFrame
  end

  def check_authorization!(server : Server, request : HTTP::Request, response : HTTP::Server::Response?)
    case server_authorization = server.authorization
    in .no_authorization?
    in .basic?
      check_basic_authorization! server: server, authorization: server_authorization, request: request, response: response
    end
  end

  private def check_basic_authorization!(server : Server, authorization : Frames::AuthorizationFlag, request : HTTP::Request, response : HTTP::Server::Response?)
    begin
      raise Exception.new String.build { |io| io << "Session.check_basic_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers is empty!" } unless request_headers = request.headers
    rescue ex
      response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: @source rescue nil

      raise ex
    end

    if headers_authorization = request_headers["Proxy-Authorization"]?
      check_basic_authorization! server: server, authorization: authorization, request: request, response: response, value: headers_authorization
      request.headers.delete "Proxy-Authorization"

      return
    end

    if headers_sec_websocket_protocol = request_headers["Sec-WebSocket-Protocol"]?
      check_sec_websocket_protocol_authorization! server: server, authorization: authorization, request: request, response: response, value: headers_sec_websocket_protocol

      return
    end

    response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: request.version, body_io: nil
    response.to_io io: @source rescue nil

    raise Exception.new String.build { |io| io << "Session.check_basic_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers[Authorization] or HTTP::Headers[Sec-WebSocket-Protocol] does not exists!" }
  end

  {% for authorization_type in ["basic", "sec_websocket_protocol"] %}
  private def check_{{authorization_type.id}}_authorization!(server : Server, authorization : Frames::AuthorizationFlag, request : HTTP::Request, response : HTTP::Server::Response?, value : String) : Bool
    {% if "basic" == authorization_type %}
      authorization_headers_key = "Proxy-Authorization"
    {% else %}
      authorization_headers_key = "Sec-WebSocket-Protocol"
    {% end %}

    begin
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] is empty!" } if value.empty?
    rescue ex
      response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: @source rescue nil

      raise ex
    end

    begin
      {% if "basic" == authorization_type %}
        authorization_type, delimiter, base64_user_name_password = value.rpartition ' '
      {% else %}
        value_split = value.split ", "
        raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] Less than 2 items (authorizationType, UserNamePassword)!" } if 2_i32 > value_split.size

        authorization_type = value_split.first
        base64_user_name_password = value_split[1_i32]
      {% end %}

      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] authorizationType or Base64UserNamePassword is empty!" } if authorization_type.empty? || base64_user_name_password.empty?
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] type is not Basic! (" << authorization_type << ")" } unless "Basic" == authorization_type

      {% if "basic" == authorization_type %}
        decoded_base64_user_name_password = Base64.decode_string base64_user_name_password rescue nil rescue nil
      {% else %}
        decoded_base64_user_name_password = Frames.decode_sec_websocket_protocol_authorization! authorization: base64_user_name_password rescue nil
      {% end %}

      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] Base64 decoding failed!" } unless decoded_base64_user_name_password
      user_name, delimiter, password = decoded_base64_user_name_password.rpartition ':'
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] username or password is empty!" } if user_name.empty? || password.empty?

      permission_type = server.on_auth.try &.call(user_name, password) || Frames::PermissionFlag::Passed
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects authorizationFlag to be " << authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] onAuth callback returns Denied!" } if permission_type.denied?
    rescue ex
      response = HTTP::Client::Response.new status_code: 401_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: @source rescue nil

      raise ex
    end

    {% if "sec_websocket_protocol" == authorization_type %}
      response.try &.headers["Sec-WebSocket-Protocol"] = authorization_type
    {% end %}

    self.authorize_frame = Frames::Authorize.new authorizationType: Frames::AuthorizationFlag::Basic, userName: user_name, password: password

    true
  end
  {% end %}
end
