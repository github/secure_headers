class OtherThingsController < ApplicationController
  ensure_security_headers :csp => {:default_src => 'self', :disable_fill_missing => true}
  def index

  end

  def other_action
    render :text => 'yooooo'
  end

  def secure_header_options_for(header, options)
    if params[:action] == "other_action"
      if header == :csp
        options.merge(:style_src => 'self')
      end
    else
      options
    end
  end
end
