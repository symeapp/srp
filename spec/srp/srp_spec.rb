require 'spec_helper'
require 'srp'

describe SRP do
  
  it "should successfully authenticate" do
    
    username, password = 'alice', 'password123'
    
    # Client creates a salt and verifier
    client = CSRP::Client.new('sha-1', 1024)
    client.salt = "beb25379d1a8581eb5a727673a2441ee"
    client.create_verifier(username, password)
    
    puts "Salt: " + client.salt
    puts "Verifier: " + client.verifier
    
    # Server stores salt and verifier
    server = CSRP::Server.new('sha-1', 1024)
    
    server.set_credentials(username,
      client.salt, client.verifier)
    
    # Client invents A and starts authentication
    client.start_authentication
    puts "A: " + client.A
    
    # Server invents B and starts authentication
    server.start_authentication(client.A)
    puts "B: " + server.B
    
    # Client processes challenge and calculates M
    client.process_challenge(server.B)
    puts "M: " + client.M
    
    # Server verifies M and calculates HAMK
    verified = server.verify_session(client.M)
    puts verified ? "HAMK: " + server.HAMK : "FAILED"
    
  end
  
end