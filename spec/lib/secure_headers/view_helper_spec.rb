require 'spec_helper'
require 'pry'
require 'activesupport'
module SecureHeaders
  describe ViewHelpers do
    include ViewHelpers
    include ActionView::Helpers::CaptureHelper
    include ActionView::Helpers::JavaScriptHelper

    describe "#nonced_javascript_tag" do

      it 'works with a block' do
        binding.pry
        nonced_javascript_tag("alert(1)")
      end

      it 'works without a block'

      context 'with extra options' do
        it 'works with a block'

        it 'works without a block'

      end
    end
  end
end
