::SecureHeaders::Configuration.configure do |config|
  config.hsts = { :max_age => 10.years.to_i.to_s, :include_subdomains => false }
  config.x_frame_options = 'SAMEORIGIN'
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = {:value => 1, :mode => 'block'}
  csp = {
    :default_src => "self",
    :disable_chrome_extension => true,
    :disable_fill_missing => true,
    :report_uri => 'somewhere',
    :enforce => false # false means warnings only
  }

  config.csp = csp
end
