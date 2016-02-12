lib = File.expand_path('../lib/', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'customjwt/version'

Gem::Specification.new do |spec|
  spec.name = 'customjwt'
  spec.version = CUSTOMJWT.gem_version
  spec.authors = [
    'Jeff Lindsay',
    'Tim Rudat'
  ]
  spec.email = 'timrudat@gmail.com'
  spec.summary = 'JSON Web Token implementation in Ruby'
  spec.description = 'A pure ruby implementation of the RFC 7519 OAuth JSON Web Token (CUSTOMJWT) standard.'
  spec.homepage = 'http://github.com/customjwt/ruby-customjwt'
  spec.license = 'MIT'

  spec.files = `git ls-files -z`.split("\x0")
  spec.executables = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = %w(lib)

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'simplecov-json'
  spec.add_development_dependency 'codeclimate-test-reporter'
end
