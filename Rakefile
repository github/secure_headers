#!/usr/bin/env rake
require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'net/http'
require 'net/https'

desc "Run RSpec"
RSpec::Core::RakeTask.new do |t|
  t.verbose = false
   t.rspec_opts = "--format progress"
end

task :default => :all_spec

desc "Run all specs, and test fixture apps"
task :all_spec => :spec do
  pwd = Dir.pwd
  Dir.chdir 'fixtures/rails_3_2_12'
  puts Dir.pwd
  str = `bundle install >> /dev/null; bundle exec rspec spec`
  puts str
  unless $? == 0
    Dir.chdir pwd
    fail "Header tests with app not using initializer failed exit code: #{$?}"
  end

  Dir.chdir pwd
  Dir.chdir 'fixtures/rails_3_2_12_no_init'
  puts Dir.pwd
  puts `bundle install >> /dev/null; bundle exec rspec spec`

  unless $? == 0
    fail "Header tests with app not using initializer failed"
    Dir.chdir pwd
  end
end

begin
  require 'rdoc/task'
rescue LoadError
  require 'rdoc/rdoc'
  require 'rake/rdoctask'
  RDoc::Task = Rake::RDocTask
end

RDoc::Task.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'SecureHeaders'
  rdoc.options << '--line-numbers'
  rdoc.rdoc_files.include('lib/**/*.rb')
end

UPDATE_URI = 'https://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1'
CA_FILE = File.expand_path(File.join('..', 'config', 'curl-ca-bundle.crt'), __FILE__)
task :fetch_ca_bundle do
  begin
    FileUtils.cp CA_FILE, CA_FILE + ".bak"
    uri = URI.parse(UPDATE_URI)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.ca_file = CA_FILE
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    request = Net::HTTP::Get.new(uri.request_uri)

    ca_file = StringIO.new(http.request(request).body)
    File.open(CA_FILE, 'w') do |f|
      f.puts mozilla_license
    end

    while line = ca_file.gets
      next if line =~ /^#/
      next if line =~ /^\s*$/
      line.chomp!

      if line =~ /CKA_LABEL/
        label,type,cert_name = line.split(' ',3)
        cert_name.sub!(/^"/, "")
        cert_name.sub!(/"$/, "")
        next
      end
      if line =~ /CKA_VALUE MULTILINE_OCTAL/
        puts "reading cert for #{cert_name}"
        data=''
        while line = ca_file.gets
          break if line =~ /^END/
          line.chomp!
          line.gsub(/\\([0-3][0-7][0-7])/) { data += $1.oct.chr }
        end

        open(CA_FILE, "a") do |fp|
          puts "Appending"
          fp.puts cert_name
          fp.puts "================"
          fp.puts "-----BEGIN CERTIFICATE-----"
          fp.puts [data].pack("m*")
          fp.puts "-----END CERTIFICATE-----"
          fp.puts
        end
        puts "Parsing: " + cert_name
      end
    end

    FileUtils.rm CA_FILE + ".bak"
  rescue => e
    puts "ERRROR #{e}"
    puts e.backtrace
    FileUtils.mv CA_FILE + '.bak', CA_FILE
  end
end


def mozilla_license
<<-EOM
##  generated using a modified version of http://curl.haxx.se/mail/lib-2004-07/att-0134/parse-certs.sh
##
## lib/ca-bundle.crt -- Bundle of CA Root Certificates
##
## Certificate data from Mozilla as of: Tue Mar 27 20:21:58 2012
##
## This is a bundle of X.509 certificates of public Certificate Authorities
## (CA). These were automatically extracted from Mozilla's root certificates
## file (certdata.txt).  This file can be found in the mozilla source tree:
## http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1
##
## It contains the certificates in PEM format and therefore
## can be directly used with curl / libcurl / php_curl, or with
## an Apache+mod_ssl webserver for SSL client authentication.
## Just configure this file as the SSLCACertificateFile.
##

# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the Netscape security libraries.
#
# The Initial Developer of the Original Code is
# Netscape Communications Corporation.
# Portions created by the Initial Developer are Copyright (C) 1994-2000
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
EOM
end
