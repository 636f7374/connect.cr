struct CONNECT::Frames
  struct Destination < Frames
    property request : HTTP::Request
    property tunnelMode : Bool?
    property trafficType : TrafficType?
    property addressType : AddressFlag?
    property destinationIpAddress : Socket::IPAddress?
    property destinationAddress : Address?

    def initialize(@request : HTTP::Request)
      @tunnelMode = nil
      @trafficType = nil
      @addressType = nil
      @destinationIpAddress = nil
      @destinationAddress = nil
    end

    def get_destination_address : Socket::IPAddress | Address
      raise Exception.new "Destination.get_destination_address: Destination.addressType cannot be Nil!" unless address_type = addressType

      case address_type
      in .ipv6?
        raise Exception.new "Destination.get_destination_address: Destination.destinationIpAddress cannot be Nil!" unless destination_ip_address = destinationIpAddress
        destination_ip_address
      in .ipv4?
        raise Exception.new "Destination.get_destination_address: Destination.destinationIpAddress cannot be Nil!" unless destination_ip_address = destinationIpAddress
        destination_ip_address
      in .domain?
        raise Exception.new "Destination.get_destination_address: Destination.destinationAddress cannot be Nil!" unless destination_address = destinationAddress
        destination_address
      end
    end
  end
end
