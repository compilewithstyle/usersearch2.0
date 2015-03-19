#!/usr/bin/env ruby

=begin rdoc

	Author:
		Nicholas Siow | compilewithstyle@gmail.com

	Description:
		Simple Ruby wrapper for the user-lookup procedure. Parses and validates user
		input and then constructs a MySQL query to find the user based on the given
		information.

		The majority of this script is devoted to input validation and error handling.

=end

require 'json'
require 'time'
require 'mysql'
require 'ostruct'
require 'optparse'

#--------------------------------------------------------------------------------
#	debugging helpers
#--------------------------------------------------------------------------------

# turn on/off debugging based on command-line arguments
$debug = false

# turn on/off JSON printing based on command-line arguments
$json = false

def debug( msg )
	puts "[DEBUG]: #{msg}" if $debug
end

def err( msg )
	puts "[ERROR]: #{msg}"
	exit
end

#--------------------------------------------------------------------------------
#	define program constants
#--------------------------------------------------------------------------------

DB_PASSWORD = `cat ./password`.strip

# use a here-doc to define the usersearch MYSQL procedure
PROCEDURE = <<-PROC

	SELECT k.ts,
	       INET_NTOA(k.eip),
	       k.eport,
	       INET_NTOA(k.iip),
	       k.mac,
	       registration.wustl_key
	FROM
	  (SELECT dhcp.ts,
	          f.eip,
	          f.eport,
	          dhcp.iip,
	          dhcp.mac
	   FROM (
	           (SELECT eip,
	                   eport,
	                   iip
	            FROM firewall
	            WHERE eip = INET_ATON('{eip}')
	              AND eport = {eport}
	              AND (firewall.ts BETWEEN {fw_lower_ts_bound} AND {fw_upper_ts_bound})
	            ORDER BY Abs(firewall.ts - {ts}) LIMIT 1) AS f
	         JOIN dhcp ON f.iip = dhcp.iip)
	   WHERE (dhcp.ts BETWEEN {dhcp_lower_ts_bound} AND {dhcp_upper_ts_bound})
	   ORDER BY Abs(dhcp.ts - {ts}) LIMIT 1) AS k
	JOIN registration ON k.mac = registration.mac;

PROC

# the max time-delta (in seconds) that a DHCP ack can be from the
#   given connection timestamp
MAX_DHCP_TDELTA = 60*60*12

# the max time-delta (in seconds) that a firewall translation can be from the
#   given connection timestamp
MAX_FIREWALL_TDELTA = 30

#--------------------------------------------------------------------------------
#
#--------------------------------------------------------------------------------

#--------------------------------------------------------------------------------
#	main program routine
#--------------------------------------------------------------------------------

# parse command-line arguments
OptionParser.new do |opts|
	opts.banner = "USAGE: usersearch.rb [OPTIONS] <TS> <IP> <PORT>"

	opts.on('-j', '--json', 'Print results in JSON format') do |json|
		$json = true
	end

	opts.on('-d', '--debug', 'Turn on program debugging') do |debug|
		$debug = true
	end

	opts.on('-h', '--help', 'Display this message') do |help|
		puts opts
	end

	if ARGV.size < 3
		puts opts
		exit
	end
end.parse!

# use select statements to parse out the arguments from what is given
input = OpenStruct.new
ARGV.each do |a|
	case a
		when /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
			input.ip = a
		when /^\d{1,5}$/
			input.port = a
		when /^\d{10,}(?:\.\d+)?$/
			input.ts = Time.at(a.to_f).to_i
		else
			begin
				input.ts = Time.parse(a).to_i
			rescue ArgumentError
				err "Not sure what to do with argument: #{a}"
			end
	end
end

# make sure all of the required variables are present
[ :ts, :ip, :port ].each do |req|
	if input[req].nil?
		err "Missing required argument: #{req}"
	else
		debug "Found #{req}='#{input[req]}'"
	end
end

# read in the sql template (stripping extra whitespace)
#   and make the appropriate substitutions
template = PROCEDURE.gsub(/\s+/, ' ').strip
template.gsub! "{eip}", input.ip.to_s
template.gsub! "{eport}", input.port.to_s
template.gsub! "{ts}", input.ts.to_i.to_s
template.gsub! "{dhcp_lower_ts_bound}", (input.ts - MAX_DHCP_TDELTA).to_s
template.gsub! "{dhcp_upper_ts_bound}", (input.ts + MAX_DHCP_TDELTA).to_s
template.gsub! "{fw_lower_ts_bound}", (input.ts - MAX_FIREWALL_TDELTA).to_s
template.gsub! "{fw_upper_ts_bound}", (input.ts + MAX_FIREWALL_TDELTA).to_s
debug "Using SQL call: <<<\n#{template}\n>>>"

begin
	# connect to the database
	conn = Mysql.new 'localhost', 'nsiow', DB_PASSWORD, 'usersearch_test'

	# submit your query
	res = conn.query template

	# retrieve the results
	num = res.num_rows
	debug "Received #{num} rows from MySQL"

	# print statement and exit if no results are found
	if num == 0
		puts "No results found."
		exit
	end

	# print each result
	counter = 0
	res.each_hash do |r|
		puts " Option #{counter} ".center 60, '-'
		longest_field = r.keys.map { |x| x.length }.max
		r.each do |k,v|
			puts "#{k.ljust longest_field, ' '}: #{v}"
		end
		puts '-'*60
	end

	puts 'done.'
rescue Mysql::Error => e
	err "#{e.error}"
ensure
	puts 'closing database.'
	conn.close if conn
end
