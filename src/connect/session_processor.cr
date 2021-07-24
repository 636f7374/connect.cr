class CONNECT::SessionProcessor
  property session : Session
  getter callback : Proc(Transfer, UInt64, UInt64, Nil)?
  getter heartbeatCallback : Proc(Transfer, Time::Span, Nil)?

  def initialize(@session : Session, @callback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, @heartbeatCallback : Proc(Transfer, Time::Span, Nil)? = nil)
  end

  def perform(server : Server)
    return session.cleanup unless outbound = session.outbound

    transfer = Transfer.new source: session, destination: outbound, callback: callback, heartbeatCallback: heartbeat_proc
    set_transfer_options transfer: transfer
    session.set_transfer_tls transfer: transfer, reset: true

    perform transfer: transfer
    transfer.reset!
  end

  private def perform(transfer : Transfer)
    transfer.perform

    loop do
      if transfer.done?
        transfer.cleanup
        session.reset reset_tls: true

        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  private def set_transfer_options(transfer : Transfer)
    # This function is used as an overridable.
    # E.g. SessionID.

    __set_transfer_options transfer: transfer
  end

  private def __set_transfer_options(transfer : Transfer)
  end

  private def heartbeat_proc : Proc(Transfer, Time::Span, Nil)?
    ->(transfer : Transfer, heartbeat_interval : Time::Span) do
      return sleep heartbeat_interval unless _heartbeat_callback = heartbeatCallback
      _heartbeat_callback.call transfer, heartbeat_interval
    end
  end
end
