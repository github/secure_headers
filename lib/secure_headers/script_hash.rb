require 'rack'

module SecureHeaders
	class ScriptHash
		 def initialize(app)
	    @app = app
  	end

	  def call(env)
	    status, headers, response = @app.call(env)

	    if headers["Content-Type"] && headers["Content-Type"].include?("text/html") && env['script_hashes'].present?
	    	# jank to make sure we're messing w/ the right header
	    	header_name = ContentSecurityPolicy.new(nil, :ua => env["HTTP_USER_AGENT"]).name

	    	csp = headers[header_name]
	    	source_expression = hash_source_expression(env['script_hashes'])

	    	# nice and dirty. probably should just pass the ContentSecurityPolicy object
	    	# and set the value from here rather than string substition after the fact :P
	    	if csp =~ /script-src/
	    		csp.sub!(/script-src/, 'script-src ' + source_expression)
	    	else
	    		csp += "script-src 'none' " + source_expression
	    	end

	    	headers['Content-Security-Policy-Report-Only'] = csp
	    end
	    [status, headers, response]
	  end

	  	# need to settle on stuffs
		def hash_source_expression(hashes, format = "sha256", delimeter = "-", hash_delimeter = " ", wrapper = "'")
			wrapper + format + delimeter + hashes.join(hash_delimeter) + wrapper
		end
	end
end