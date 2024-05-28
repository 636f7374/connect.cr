module CONNECT::SessionProcessor
  private def self.set_transfer_options(transfer : Transfer, session : Session, exceed_threshold_flag : Transfer::ExceedThresholdFlag)
    # This function is used as an overridable.
    # E.g. sessionid.

    __set_transfer_options transfer: transfer, session: session, exceed_threshold_flag: exceed_threshold_flag
  end

  private def self.__set_transfer_options(transfer : Transfer, session : Session, exceed_threshold_flag : Transfer::ExceedThresholdFlag)
    transfer.heartbeatInterval = session.options.session.heartbeatInterval
    transfer.aliveInterval = session.options.session.aliveInterval
  end

  def self.perform(server : Server, session : Session, finish_callback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, heartbeat_callback : Proc(Transfer, Time::Span, Bool)? = nil) : Nil
    unless session_destination = session.destination
      session.source.close rescue nil

      return
    end

    transfer = Transfer.new source: session.source, destination: session_destination, finishCallback: finish_callback, heartbeatCallback: (heartbeat_callback ? heartbeat_proc(heartbeat_callback: heartbeat_callback) : heartbeat_proc(heartbeat_callback: nil))
    set_transfer_options transfer: transfer, session: session, exceed_threshold_flag: Transfer::ExceedThresholdFlag::SENT
    transfer.perform

    loop do
      case transfer
      when .sent_done?
        transfer.destination.close rescue nil unless transfer.receive_done?

        break
      when .receive_done?
        transfer.source.close rescue nil unless transfer.sent_done?

        break
      end

      sleep 0.01_f32.seconds
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      break
    end

    transfer.source.close rescue nil
    transfer.destination.try &.close rescue nil

    nil
  end

  private def self.heartbeat_proc(heartbeat_callback : Proc(Transfer, Time::Span, Bool)? = nil) : Proc(Transfer, Time::Span, Bool)?
    ->(transfer : Transfer, heartbeat_interval : Time::Span) do
      heartbeat = heartbeat_callback ? heartbeat_callback.call(transfer, heartbeat_interval) : true

      unless heartbeat
        sleep heartbeat_interval

        return true
      end

      return !!heartbeat
    end
  end
end
