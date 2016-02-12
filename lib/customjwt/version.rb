# encoding: utf-8

# Moments version builder module
module CUSTOMJWT
  def self.gem_version
    Gem::Version.new VERSION::STRING
  end

  # Moments version builder module
  module VERSION
    # major version
    MAJOR = 1
    # minor version
    MINOR = 5
    # tiny version
    TINY  = 3
    # alpha, beta, etc. tag
    PRE   = 'dev'

    # Build version string
    STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')
  end
end
