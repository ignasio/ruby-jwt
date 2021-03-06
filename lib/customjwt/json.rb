require 'json'

module CUSTOMJWT
  # JSON fallback implementation or ruby 1.8.x
  module Json
    def decode_json(encoded)
      JSON.parse(encoded)
    rescue JSON::ParserError
      raise CUSTOMJWT::DecodeError, 'Invalid segment encoding'
    end

    def encode_json(raw)
      JSON.generate(raw)
    end
  end
end
