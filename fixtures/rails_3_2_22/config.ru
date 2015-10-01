# This file is used by Rack-based servers to start the application.

require ::File.expand_path('../config/environment',  __FILE__)
run Rails3212::Application

require 'secure_headers/headers/content_security_policy/script_hash_middleware'
use ::SecureHeaders::ContentSecurityPolicy::ScriptHashMiddleware
