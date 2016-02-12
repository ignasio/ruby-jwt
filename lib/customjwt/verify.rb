module CUSTOMJWT
  # CUSTOMJWT verify methods
  module Verify
    def self.verify_expiration(payload, options)
      return unless payload.include?('exp')

      if payload['exp'].to_i < (Time.now.to_i - options[:leeway])
        fail(CUSTOMJWT::ExpiredSignature, 'Signature has expired')
      end
    end

    def self.verify_not_before(payload, options)
      return unless payload.include?('nbf')

      if payload['nbf'].to_i > (Time.now.to_i + options[:leeway])
        fail(CUSTOMJWT::ImmatureSignature, 'Signature nbf has not been reached')
      end
    end

    def self.verify_iss(payload, options)
      return unless options[:iss]

      if payload['iss'].to_s != options[:iss].to_s
        fail(
          CUSTOMJWT::InvalidIssuerError,
          "Invalid issuer. Expected #{options[:iss]}, received #{payload['iss'] || '<none>'}"
        )
      end
    end

    def self.verify_iat(payload, options)
      return unless payload.include?('iat')

      if !(payload['iat'].is_a?(Integer)) || payload['iat'].to_i > (Time.now.to_i + options[:leeway])
        fail(CUSTOMJWT::InvalidIatError, 'Invalid iat')
      end
    end

    def self.verify_jti(payload, _options)
      if _options[:verify_jti].class == Proc
        fail(CUSTOMJWT::InvalidJtiError, 'Invalid jti') unless _options[:verify_jti].call(payload['jti'])
      else
        fail(CUSTOMJWT::InvalidJtiError, 'Missing jti') if payload['jti'].to_s == ''
      end
    end

    def self.verify_aud(payload, options)
      return unless options[:aud]

      if payload[:aud].is_a?(Array)
        fail(
          CUSTOMJWT::InvalidAudError,
          'Invalid audience'
        ) unless payload['aud'].include?(options[:aud].to_s)
      else
        fail(
          CUSTOMJWT::InvalidAudError,
          "Invalid audience. Expected #{options[:aud]}, received #{payload['aud'] || '<none>'}"
        ) unless payload['aud'].to_s == options[:aud].to_s
      end
    end

    def self.verify_sub(payload, options)
      return unless options[:sub]


      fail(
        CUSTOMJWT::InvalidSubError,
        "Invalid subject. Expected #{options[:sub]}, received #{payload['sub'] || '<none>'}"
      ) unless payload['sub'].to_s == options[:sub].to_s
    end
  end
end
