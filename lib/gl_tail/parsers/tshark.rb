# gl_tail.rb - OpenGL visualization of your server traffic
# Copyright 2007 Erlend Simonsen <mr@fudgie.org>
#
# Licensed under the GNU General Public License v2 (see LICENSE)
#

# Parser which handles tshark logs
class TSharkParser < Parser

  def parse( line )
    if (line.include?('->'))
      time, srcip, arrow, destip, type, = line.split(" ")
      add_activity(:block => 'users', :name => srcip)
      add_activity(:block => 'types', :name => type)

    elsif (line.include?('HTTP GET') or line.include?('HTTP POST'))
      add_activity(:block => 'HTTP GET/POST', :name => destip)

    elsif (line.include?('DNS Standard query A'))
      foo, name = line.split(" A ")
      if(name != nil)
        add_event(
          :block => 'status',
          :name => "DNS Queries",
          :message => "DNS Request: " + name,
          :update_stats => true,
          :color => [1.5, 1.0, 0.5, 1.0])
        add_activity(:block => 'dns queries', :name => name)
      end

    elsif (line.include?('NBNS Registration NB '))
      name = line.split(' NBNS Registration NB ')[1].split('<')[0]
      add_activity(:block => 'nb registration', :name => name)

    elsif (line.include?('BROWSER Host Announcement '))
      name = line.split("BROWSER Host Announcement ")[1].split(',')[0]
      add_activity(:block => 'nb browser host', :name => name)

    elsif (line.include?('BROWSER Local Master Announcment '))
      name = line.split("BROWSER Local Master Announcment ")[1].split(',')[0]
      add_activity(:block => 'nb local master', :name => name)

    elsif (line.include?(' DNS Standard query PTR '))
      name = line.split("DNS Standard query PTR ")[1].split(".in-addr.arpa")[0].split(".").reverse.join('.')
      add_activity(:block => 'dns reverse', :name => name)

    elsif (line.include?('ARP Who has'))
      who,tell = line.split("ARP Who has ")[1].split('?')
      tell = tell.split("Tell ")[1]
      add_activity(:block => 'arp who', :name => who)
      add_activity(:block => 'arp tell',:name => tell)
    end
  end

end
