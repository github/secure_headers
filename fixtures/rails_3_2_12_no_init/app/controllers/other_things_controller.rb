class OtherThingsController < ApplicationController
  ensure_security_headers :csp => {
    :default_src => 'self',
    :disable_chrome_extension => true,
    :disable_fill_missing => true,
    :script_src => 'self nonce',
    :report_uri => 'somewhere'
  },
  :x_xss_protection => {
    :value => 1,
    :mode => 'block'
    },
  :hsts => {
    :max_age => "315576000"
  }

  def index

  end
end
