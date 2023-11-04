##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/Placidina/metasploit
##

require 'net-http2'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTP/2 Rapid Reset DDoS Attack',
        'Author' => [
          'Alan Placidina Maria' # metasploit module
        ],
        'References' => [
          ['CVE', '2023-44487'],
          ['URL', 'https://aws.amazon.com/blogs/security/how-aws-protects-customers-from-ddos-events/'],
          ['URL', 'https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack'],
          ['URL', 'https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/'],
          ['URL', 'https://msrc.microsoft.com/blog/2023/10/microsoft-response-to-distributed-denial-of-service-ddos-attacks-against-http/2/']
        ],
        'DisclosureDate' => '2023-10-10'
      )
    )

    register_options(
      [
        OptString.new('URL', [true, 'The request URI', '']),
        OptString.new('PROXY', [false, 'Proxy url', '']),
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 10]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 5])
      ]
    )
  end

  def rlimit
    datastore['RLIMIT']
  end

  def thread_count
    datastore['THREADS']
  end

  def targeturl
    datastore['URL']
  end

  def opts
    if !datastore['PROXY'].empty?
      uri = URI.parse(datastore['PROXY'])
      return {
        proxy_addr: "#{uri.scheme}://#{uri.host}",
        proxy_port: uri.port.to_s
      }
    end
  end

  def run
    starting_thread = 1
    while starting_thread < rlimit
      ubound = [rlimit - (starting_thread - 1), thread_count].min
      print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

      threads = []
      1.upto(ubound) do |i|
        threads << framework.threads.spawn("Module(#{refname})-request#{(starting_thread - 1) + i}", false, i) do |_i|
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ctx.next_protos = ['h2']

          # TODO: code here
        end
      end

      threads.each(&:join)
      print_good("Finished executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}")
      starting_thread += ubound
    end
  end
end
