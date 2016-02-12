require 'customjwt/json'
require 'customjwt/verify'

# CUSTOMJWT::Decode module
module CUSTOMJWT
  extend CUSTOMJWT::Json

  # Decoding logic for CUSTOMJWT
  class Decode
    attr_reader :header, :payload, :signature

    def initialize(customjwt, key, verify, options, &keyfinder)
      @customjwt = customjwt
      @key = key
      @verify = verify
      @options = options
      @keyfinder = keyfinder
    end

    def decode_segments
      header_segment, payload_segment, crypto_segment = raw_segments(@customjwt, @verify)
      @header, @payload = decode_header_and_payload(header_segment, payload_segment)
      @signature = base64url_decode(crypto_segment.to_s) if @verify
      signing_input = [header_segment, payload_segment].join('.')
      [@header, @payload, @signature, signing_input]
    end

    def raw_segments(customjwt, verify)
      segments = customjwt.split('.')
      required_num_segments = verify ? [3] : [2, 3]
      fail(CUSTOMJWT::DecodeError, 'Not enough or too many segments') unless required_num_segments.include? segments.length
      segments
    end
    private :raw_segments

    def decode_header_and_payload(header_segment, payload_segment)
      header = CUSTOMJWT.decode_json(base64url_decode(header_segment))
      payload = CUSTOMJWT.decode_json(base64url_decode(payload_segment))
      [header, payload]
    end
    private :decode_header_and_payload

    def base64url_decode(str)
      str += '=' * (4 - str.length.modulo(4))
      Base64.decode64(str.tr('-_', '+/'))
    end
    private :base64url_decode

    def verify
      @options.each do |key, val|
        next unless key.to_s.match(/verify/)

        Verify.send(key, payload, @options) if val
      end
    end
  end
end
