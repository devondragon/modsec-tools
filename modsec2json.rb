#!/usr/bin/env ruby

# Convert ModSecurity audit log to JSON Lines
#
# Usage:
#   modsec_audit2jsonl.rb modsed_audit.log
#   Or
#   cat modsed_audit.log | modsec_audit2jsonl.rb

require "json"
require "strscan"

# Log format is described in:
# https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats

SEPARATOR = /^--([0-9a-f]+)-([A-Z])--$/

class EntryHeader
  def <<(line)
	return if line.strip == ""
		if match = line.match(/\[(.*)?\s(.*)\]/i)
			@date, @timezone = match.captures
		end
  end

  def to_json(*args)
	{ "date" => @date,
	  "timezone" => @timezone,
	}.to_json(*args)
  end
end

class RequestHeader
  def initialize
	@headers = {}
  end

  def <<(line)
	return if line.strip == ""
	if @method
	  key, value = line.split(": ", 2)
	  @headers[key] = value
	else
	  @method, @path, @version = line.split(" ")
	end
  end

  def to_json(*args)
	{ "method" => @method,
	  "path" => @path,
	  "version" => @version,
	  "headers" => @headers,
	}.to_json(*args)
  end
end

class ResponseHeader
  def initialize
	@headers = {}
	@headers.compare_by_identity
  end

  def <<(line)
	return if line.strip == ""
	if @status
	  key, value = line.split(": ", 2)
	  @headers[key] = value
	else
	  @version, @status, @reason = line.split(" ")
	end
  end

  def to_json(*args)
	{ "version" => @version,
	  "status" => @status,
	  "reason" => @reason,
	  "headers" => @headers.to_a,
	}.to_json(*args)
  end
end

class AuditLogTrailer
  class Message
	def initialize(line)
	  @data = {}
	  parse(line)
	end

	def parse(line)
	  if line =~ /(.+?) (\[.+\])/
		message, data = $~.captures
		@data = parse_data(data)
	  else
		message = line
	  end
	  @data["msg"] ||= ""
	  @data["message"] = message.strip
	end

	def parse_data(line)
	  data = {}
	  s = StringScanner.new(line)
	  s.scan(/\s*/)

	  until s.eos?
		s.scan(/\[/)
		key = s.scan(/.+? /).strip

		value = ""
		s.scan(/"/)
		begin
		  value << (s.scan(/\\./) || s.scan(/[^\\"]+/) || "")
		end until s.scan(/"/) || s.eos? # 途中で truncate されてる場合があるので eos チェック

		s.scan(/\]\s*/)

		data[key] = value
	  end
	  data
	end

	def to_json(*args)
	  @data.to_json(*args)
	end
  end

  def initialize
	@metadata = {
	  "Messages" => []
	}
  end

  def <<(line)
	return if line.strip == ""
	if line =~ /^Message: (.+)/
	  @metadata["Messages"] << Message.new($1)
	else
	  key, value = line.split(": ", 2)
	  @metadata[key] = value
	end
  end

  def to_json(*args)
	@metadata.to_json(*args)
  end
end

transaction = nil
section = nil

while line = gets
  line.strip!
  if line =~ SEPARATOR
	boundary, section_id = $~.captures
	case section_id
	when "A"
	  transaction = {}
	  section = EntryHeader.new
	  transaction["EntryHeader"] = section
	when "B"
	  section = RequestHeader.new
	  transaction["RequestHeader"] = section
	when "C"
	  section = ""
	  transaction["RequestBody"] = section
	when "E"
	  section = ""
	  transaction["IntendedResponseBody"] = section
	when "F"
	  section = ResponseHeader.new
	  transaction["ResponseHeader"] = section
	when "H"
	  section = AuditLogTrailer.new
	  transaction["AuditLogTrailer"] = section
	when "Z"
	  puts transaction.to_json
	  section = nil
	  transaction = nil
	else
	  section = ""
	  transaction[section_id] = section
	end
  else
	section << line if section
  end
end