struct CONNECT::Frames
  struct Authenticate < Frames
    property authenticationType : AuthenticationFlag
    property userName : String
    property password : String

    def initialize(@authenticationType : AuthenticationFlag, @userName : String, @password : String)
    end
  end
end
