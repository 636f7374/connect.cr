struct CONNECT::Frames
  struct Authorize < Frames
    property authorizationType : AuthorizationFlag
    property userName : String
    property password : String

    def initialize(@authorizationType : AuthorizationFlag, @userName : String, @password : String)
    end
  end
end
