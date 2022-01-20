class CONNECT::SessionProcessor
  property session : Session
  getter finishCallback : Proc(Transfer, UInt64, UInt64, Nil)?
  getter heartbeatCallback : Proc(Transfer, Time::Span, Bool)?

  def initialize(@session : Session, @finishCallback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, @heartbeatCallback : Proc(Transfer, Time::Span, Bool)? = nil)
  end

  def perform(server : Server) : Bool
    unless outbound = session.outbound
      session.syncCloseOutbound = true
      session.cleanup

      return false
    end

    transfer = Transfer.new source: session, destination: outbound, finishCallback: nil, heartbeatCallback: nil
    __perform transfer: transfer
  end

  private def __perform(transfer : Transfer) : Bool
    session.syncCloseOutbound = false
    set_transfer_options transfer: transfer

    transfer.perform

    loop do
      case transfer
      when .sent_done?
        transfer.destination.close rescue nil unless transfer.destination.closed?
      when .receive_done?
        transfer.source.close rescue nil unless transfer.source.closed?
      end

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      break
    end

    session.syncCloseOutbound = true
    session.cleanup

    false
  end

  private def set_transfer_options(transfer : Transfer)
    # This function is used as an overridable.
    # E.g. SessionID.

    __set_transfer_options transfer: transfer
  end

  private def __set_transfer_options(transfer : Transfer)
    transfer.heartbeatInterval = session.options.session.heartbeatInterval
    transfer.aliveInterval = session.options.session.aliveInterval
    transfer.finishCallback = finishCallback
    transfer.heartbeatCallback = heartbeatCallback ? heartbeatCallback : heartbeat_proc
  end

  private def heartbeat_proc : Proc(Transfer, Time::Span, Bool)?
    ->(transfer : Transfer, heartbeat_interval : Time::Span) do
      _heartbeat_callback = heartbeatCallback
      heartbeat = _heartbeat_callback ? _heartbeat_callback.call(transfer, heartbeat_interval) : true

      unless _heartbeat_callback
        transfer.reset_monitor_state
        sleep heartbeat_interval

        return true
      end

      return !!heartbeat
    end
  end
end
