# encoding: utf-8
require "logstash/codecs/base"
require "logstash/util/charset"

require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/event_support/event_factory_adapter'

# RFC6587 text data.
#
# Decoding behavior: Lines will be emitted as described in rfc6587.
#
# Encoding behavior: TBD
class LogStash::Codecs::Rfc6587 < LogStash::Codecs::Base

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)
  include LogStash::PluginMixins::EventSupport::EventFactoryAdapter

  config_name "rfc6587"

  ## Set the desired text format for encoding.
  #config :format, :validate => :string

  # The character encoding used in this input. Examples include `UTF-8`
  # and `cp1252`
  #
  # This setting is useful if your log files are in `Latin-1` (aka `cp1252`)
  # or in another character set other than `UTF-8`.
  #
  # This only affects "plain" format logs since json is `UTF-8` already.
  config :charset, :validate => ::Encoding.name_list, :default => "UTF-8"

  # Change the delimiter that separates lines
  config :delimiter, :validate => :string, :default => " "

  def initialize(*params)
    super

    raise "Delimitter must be 1 character long, but got '#{@delimiter}'" if @delimiter.length != 1
    @original_field = ecs_select[disabled: nil, v1: '[event][original]']
  end

  MESSAGE_FIELD = "message".freeze

  def register
    @leftover = ""
    @converter = LogStash::Util::Charset.new(@charset)
    @converter.logger = @logger
  end

  def read(data)
    header = ""
    while (c = data.getc)
      next if ["\0", "\x00"].include?(c)  # ignore null characters
      raise "Unknown header character '#{c}'" if not [@delimiter, nil, c.to_i.to_s].include?(c)
      header += c if c
      break if c == @delimiter or data.eof or c == nil
    end
    raise "Unknown header '#{header}'" if header != "" and header.to_i == 0
    if data.eof
      @leftover = header
      return
    end

    to_read = header.to_i
    line = ""
    to_read.times do
      break if (c = data.getc) == nil
      line += c
    end

    if not line
      @leftover = header
      return
    end

    if line.length == to_read
      return line
    else
      @leftover = "#{header}#{line}"
      return
    end
  end

  def decode(data)
    data = StringIO.new @leftover + data
    while (line = read(data))
      yield new_event_from_line(line)
    end
  end

  def flush(&block)
    #remainder = @buffer.flush
    #if !remainder.empty?
    #  block.call new_event_from_line(remainder)
    #end
  end

  def encode(event)
    raise "Not implemented"
    #encoded = @format ? event.sprintf(@format) : event.to_s
    #@on_event.call(event, encoded + @delimiter)
  end

  private

  def new_event_from_line(line)
    message = @converter.convert(line)
    event = event_factory.new_event MESSAGE_FIELD => message
    event.set @original_field, message.dup.freeze if @original_field
    event
  end

end
