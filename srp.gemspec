$:.push File.expand_path('../lib', __FILE__)
require 'srp/version'

Gem::Specification.new do |s|
  
  s.name        = 'srp'
  s.version     = SRP::VERSION
  s.authors     = ['Louis Mullie']
  s.email       = ['louis.mullie@gmail.com']
  s.homepage    = 'https://github.com/symeapp/srp'
  s.summary     = %q{ Ruby wrapper around a C implementation of the SRP protocol }
  s.description = %q{ Ruby wrapper around a C interface to the OpenSSL implementation of the Secure Remote Password protocol, version 6-A. }

  s.files = Dir.glob('lib/**/*.rb') +
  Dir.glob('ext/**/*.{c,h,rb}')

  s.extensions << 'ext/srp/extconf.rb'
  s.add_development_dependency 'rspec', '~> 2.12.0'
  s.add_development_dependency 'rake'
end
