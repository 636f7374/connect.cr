class Transfer
  enum SDFlag : UInt8
    SOURCE      = 0_u8
    DESTINATION = 1_u8
  end

  enum SRFlag : UInt8
    SENT    = 0_u8
    RECEIVE = 1_u8
  end

  enum SocketSwitchExpressionFlag : UInt8
    OR  = 0_u8
    AND = 1_u8
  end

  enum ExceedThresholdFlag : UInt8
    NONE    = 0_u8
    SENT    = 1_u8
    RECEIVE = 2_u8
  end

  class TerminateConnection < Exception
  end

  property source : IO
  property destination : IO
  property finishCallback : Proc(Transfer, UInt64, UInt64, Nil)?
  property heartbeatCallback : Proc(Transfer, Time::Span, Bool)?
  getter firstAliveTime : Atomic(Int64)
  getter lastAliveTime : Atomic(Int64)
  getter monitor : Atomic(Int8)
  getter monitorCapacity : Atomic(Int8)
  getter monitorState : Hash(SRFlag, Hash(Int64, UInt64))?
  getter sentDone : Atomic(Int8)
  getter receiveDone : Atomic(Int8)
  getter sentBytes : Atomic(UInt64)
  getter receivedBytes : Atomic(UInt64)
  getter heartbeatCounter : Atomic(UInt64)
  property heartbeatInterval : Time::Span
  property aliveInterval : Time::Span
  property socketSwitchSeconds : Atomic(UInt64)
  property socketSwitchBytes : Atomic(UInt64)
  property socketSwitchExpression : Atomic(SocketSwitchExpressionFlag)
  property exceedThresholdFlag : Atomic(ExceedThresholdFlag)
  getter mutex : Mutex
  getter concurrentFibers : Set(Fiber)
  getter concurrentMutex : Mutex

  def initialize(@source : IO, @destination : IO, @finishCallback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, @heartbeatCallback : Proc(Transfer, Time::Span, Bool)? = nil)
    @firstAliveTime = Atomic(Int64).new -1_i64
    @lastAliveTime = Atomic(Int64).new -1_i64
    @monitor = Atomic(Int8).new -1_i8
    @monitorCapacity = Atomic(Int8).new Int8::MAX
    @monitorState = monitor? ? Hash(SRFlag, Hash(Int64, UInt64)).new : nil
    @sentDone = Atomic(Int8).new -1_i8
    @receiveDone = Atomic(Int8).new -1_i8
    @sentBytes = Atomic(UInt64).new 0_u64
    @receivedBytes = Atomic(UInt64).new 0_u64
    @heartbeatCounter = Atomic(UInt64).new 0_u64
    @heartbeatInterval = 3_i32.seconds
    @aliveInterval = 1_i32.minutes
    @socketSwitchSeconds = Atomic(UInt64).new 0_u64
    @socketSwitchBytes = Atomic(UInt64).new 0_u64
    @socketSwitchExpression = Atomic(SocketSwitchExpressionFlag).new SocketSwitchExpressionFlag::OR
    @exceedThresholdFlag = Atomic(ExceedThresholdFlag).new ExceedThresholdFlag::NONE
    @mutex = Mutex.new :unchecked
    @concurrentFibers = Set(Fiber).new
    @concurrentMutex = Mutex.new :unchecked
  end

  def heartbeat_counter
    @heartbeatCounter
  end

  def first_alive_time : Time
    Time.unix_ms(milliseconds: @firstAliveTime.get) rescue Time.utc
  end

  def last_alive_time : Time
    Time.unix_ms(milliseconds: @lastAliveTime.get) rescue Time.utc
  end

  def sent_exception=(value : Exception?)
    @mutex.synchronize { @sentException = value }
  end

  def sent_exception? : Exception?
    @mutex.synchronize { @sentException.dup }
  end

  def receive_exception=(value : Exception?)
    @mutex.synchronize { @receiveException = value }
  end

  def receive_exception? : Exception?
    @mutex.synchronize { @receiveException.dup }
  end

  private def socket_switch_seconds : Time::Span
    @socketSwitchSeconds.get.seconds rescue 0_i32.seconds
  end

  private def socket_switch_bytes : UInt64
    _socket_switch_bytes = @socketSwitchBytes.get
    (_socket_switch_bytes < 0_u64) ? 0_u64 : _socket_switch_bytes
  end

  {% for name in ["sent", "receive"] %}
  private def monitor_state_{{name.id}}_size : Int32?
    @mutex.synchronize do
      return unless monitor_state = monitorState
      return unless monitor_{{name.id}}_bytes = monitor_state[SRFlag::{{name.upcase.id}}]?
      monitor_{{name.id}}_bytes.size
    end
  end

  private def update_monitor_{{name.id}}_bytes(value : Int)
    return unless monitor?

    monitor_state_{{name.id}}_size.try do |_monitor_state_{{name.id}}_size|
      return unless monitor_state = monitorState
      @mutex.synchronize { monitor_state[SRFlag::{{name.upcase.id}}].clear } if monitorCapacity.get <= _monitor_state_{{name.id}}_size
    end

    @mutex.synchronize do
      return unless monitor_state = monitorState
      monitor_{{name.id}}_bytes = monitor_state[SRFlag::{{name.upcase.id}}]? || Hash(Int64, UInt64).new
      current_time = Time.local.at_beginning_of_second.to_unix

      {{name.id}}_bytes = monitor_{{name.id}}_bytes[current_time]? || 0_u64
      {{name.id}}_bytes += value

      monitor_{{name.id}}_bytes[current_time] = {{name.id}}_bytes
      monitor_state[SRFlag::{{name.upcase.id}}] = monitor_{{name.id}}_bytes
    end

    true
  end

  def get_monitor_{{name.id}}_state(all : Bool = false) : Hash(Int64, UInt64)?
    @mutex.synchronize do
      return unless monitor_state = monitorState
      monitor_{{name.id}}_bytes = monitor_state[SRFlag::{{name.upcase.id}}]?.dup || Hash(Int64, UInt64).new

      if !all && !monitor_{{name.id}}_bytes.empty?
        monitor_{{name.id}}_bytes_last_key = monitor_{{name.id}}_bytes.keys.last
        monitor_{{name.id}}_bytes_last_value = monitor_{{name.id}}_bytes[monitor_{{name.id}}_bytes_last_key]
        monitor_state[SRFlag::{{name.upcase.id}}].clear
        monitor_state[SRFlag::{{name.upcase.id}}][monitor_{{name.id}}_bytes_last_key] = monitor_{{name.id}}_bytes_last_value
        monitor_{{name.id}}_bytes.delete monitor_{{name.id}}_bytes_last_key
      end

      monitor_{{name.id}}_bytes.dup
    end
  end
  {% end %}

  def reset_monitor_state : Bool
    @mutex.synchronize { @monitorState.try &.clear }

    true
  end

  def finished?
    concurrentMutex.synchronize { concurrentFibers.all? { |fiber| fiber.dead? } }
  end

  def any_done? : Bool
    sent_done = sentDone.get.zero?
    received_done = receiveDone.get.zero?

    finished? || sent_done || received_done
  end

  def sent_done? : Bool
    sentDone.get.zero?
  end

  def receive_done? : Bool
    receiveDone.get.zero?
  end

  def monitor? : Bool
    monitor.get.zero?
  end

  def cleanup
    source.close rescue nil
    destination.close rescue nil

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?
      reset_socket

      break
    end
  end

  def cleanup(sd_flag : SDFlag, reset : Bool = true)
    case sd_flag
    in .source?
      source.close rescue nil
    in .destination?
      destination.close rescue nil
    end

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?
      reset_socket sd_flag: sd_flag if reset

      break
    end
  end

  def reset_socket
    @concurrentMutex.synchronize do
      closed_memory = IO::Memory.new 0_i32
      closed_memory.close

      @source = closed_memory
      @destination = closed_memory
    end
  end

  def reset_socket(sd_flag : SDFlag)
    @concurrentMutex.synchronize do
      closed_memory = IO::Memory.new 0_i32
      closed_memory.close

      case sd_flag
      in .source?
        @source = closed_memory
      in .destination?
        @destination = closed_memory
      end
    end
  end

  def reset_settings!(reset_socket_switch_seconds : Bool = true, reset_socket_switch_bytes : Bool = true, reset_socket_switch_expression : Bool = true) : Bool
    return false unless finished?

    @concurrentMutex.synchronize do
      @sentException = nil
      @receiveException = nil
      @firstAliveTime.set -1_i64
      @lastAliveTime.set -1_i64
      @monitorState.try &.clear
      @exceedThresholdFlag.set ExceedThresholdFlag::NONE
      @sentDone.set -1_i8
      @receiveDone.set -1_i8
      @sentBytes.set 0_u64
      @receivedBytes.set 0_u64
      @heartbeatCounter.set 0_u64
      @socketSwitchSeconds.set 0_u64 if reset_socket_switch_seconds
      @socketSwitchBytes.set 0_u64 if reset_socket_switch_bytes
      @socketSwitchExpression.set SocketSwitchExpressionFlag::OR if reset_socket_switch_expression
      @concurrentFibers.clear
    end

    true
  end

  def check_exceed_threshold?(any_side_bytes_exceed : Bool) : Bool
    return false unless exceed_threshold_flag = exceedThresholdFlag.get
    return false if exceed_threshold_flag.none?
    return false unless _first_alive_time_unix = @firstAliveTime.get

    _socket_switch_seconds = socket_switch_seconds
    _socket_switch_bytes = socket_switch_bytes
    return false if _socket_switch_seconds.zero? && _socket_switch_bytes.zero?

    _first_alive_time = first_alive_time.dup
    timed_socket_switch = (Time.utc - _first_alive_time) > _socket_switch_seconds
    _socket_switch_expression = @socketSwitchExpression.get

    if any_side_bytes_exceed
      sent_bytes_exceed = sentBytes.get > _socket_switch_bytes
      receive_bytes_exceed = receivedBytes.get > _socket_switch_bytes

      case _socket_switch_expression
      in .and?
        return true if timed_socket_switch && (sent_bytes_exceed || receive_bytes_exceed)
      in .or?
        return true if timed_socket_switch
        return true if (sent_bytes_exceed || receive_bytes_exceed)
      end

      return false
    end

    case exceed_threshold_flag
    in .sent?
      bytes_exceed = sentBytes.get > _socket_switch_bytes
    in .receive?
      bytes_exceed = receivedBytes.get > _socket_switch_bytes
    in .none?
      bytes_exceed = false
    end

    case _socket_switch_expression
    in .and?
      return true if timed_socket_switch && bytes_exceed
    in .or?
      return true if timed_socket_switch || bytes_exceed
    end

    false
  end

  {% for name in ["sent", "receive"] %}
  def strict_check_{{name.id}}_exceed_threshold? : Bool
    case exceed_threshold_flag = @exceedThresholdFlag.get
    in .sent?
      {% if name == "sent" %}
        return true if check_exceed_threshold?(any_side_bytes_exceed: true) || receive_done?
      {% else %}
        return true if sent_done?
      {% end %}
    in .receive?
      {% if name == "sent" %}
        return true if receive_done?
      {% else %}
        return true if check_exceed_threshold?(any_side_bytes_exceed: true) || sent_done?
      {% end %}
    in .none?
      {% if name == "sent" %}
        return true if receive_done?
      {% else %}
        return true if sent_done?
      {% end %}
    end

    false
  end
  {% end %}

  def perform
    @firstAliveTime.set Time.local.to_unix_ms
    @lastAliveTime.set Time.local.to_unix_ms

    sent_fiber = spawn do
      finished_set = Set(Time).new
      exception = nil

      loop do
        begin
          IO.yield_copy src: source, dst: destination do |count, length|
            @lastAliveTime.set Time.local.to_unix_ms

            sentBytes.add(length.to_u64) rescue sentBytes.set(0_u64)
            update_monitor_sent_bytes value: length

            break if strict_check_sent_exceed_threshold? if exceedThresholdFlag.get.sent?
            break if receive_done?
          end
        rescue ex : IO::CopyException
          exception = ex.cause
        end

        unless exception
          finished_set.first?.try { |first| finished_set.clear if (Time.local - first) > 5_i32.seconds }
          finished_set << Time.local
          break if finished_set.size > 10_i32
        end

        break unless exception.class == IO::TimeoutError if exception
        break if receive_done? && !exception
        break if strict_check_sent_exceed_threshold?
        break if aliveInterval <= (Time.utc - last_alive_time)
        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError
        next sleep 0.05_f32.seconds unless receive_done?

        break
      end

      self.sent_exception = exception
      @sentDone.set 0_u64
    end

    receive_fiber = spawn do
      finished_set = Set(Time).new
      exception = nil

      loop do
        begin
          IO.yield_copy src: destination, dst: source do |count, length|
            @lastAliveTime.set Time.local.to_unix_ms

            receivedBytes.add(length.to_u64) rescue receivedBytes.set(0_u64)
            update_monitor_receive_bytes value: length

            break if strict_check_receive_exceed_threshold? if exceedThresholdFlag.get.receive?
            break if sent_done?
          end
        rescue ex : IO::CopyException
          exception = ex.cause
        end

        unless exception
          finished_set.first?.try { |first| finished_set.clear if (Time.local - first) > 5_i32.seconds }
          finished_set << Time.local
          break if finished_set.size > 10_i32
        end

        break unless exception.class == IO::TimeoutError if exception
        break if sent_done? && !exception
        break if strict_check_receive_exceed_threshold?
        break if aliveInterval <= (Time.utc - last_alive_time)

        if exception.is_a?(IO::TimeoutError) && exception.try &.message.try &.starts_with?("Write")
          _destination = destination
          ex.try &.bytes.try { |_bytes| _destination.update_receive_rescue_buffer(slice: _bytes) if _destination.responds_to? :update_receive_rescue_buffer }

          break
        end

        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError
        next sleep 0.05_f32.seconds unless sent_done?

        break
      end

      self.receive_exception = exception
      @receiveDone.set 0_u64
    end

    interval_fiber = spawn do
      interval = 0.25_f32.seconds
      heartbeat_callback = heartbeatCallback
      finish_callback = finishCallback
      _last_alive_time = Time.local

      if heartbeat_callback
        loop do
          sleep interval if (Time.local - _last_alive_time) < interval

          successful = heartbeat_callback.call self, heartbeatInterval rescue nil
          @heartbeatCounter.add(1_i64) rescue nil if successful
          _last_alive_time = Time.local

          break if sent_done? || receive_done?
        end
      end

      if finish_callback
        loop do
          sleep interval if (Time.local - _last_alive_time) < interval
          break finish_callback.call self, sentBytes.get, receivedBytes.get if sent_done? && receive_done?

          _last_alive_time = Time.local
        end
      end
    end

    @concurrentMutex.synchronize do
      @concurrentFibers << sent_fiber
      @concurrentFibers << receive_fiber
      @concurrentFibers << interval_fiber
    end
  end
end
