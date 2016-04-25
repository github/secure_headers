require 'spec_helper'

module SecureHeaders
  describe ReferrerPolicy do
    specify { expect(ReferrerPolicy.make_header).to eq([ReferrerPolicy::HEADER_NAME, "origin-when-cross-origin"]) }
    specify { expect(ReferrerPolicy.make_header('no-referrer')).to eq([ReferrerPolicy::HEADER_NAME, "no-referrer"]) }

    context "valid configuration values" do
      it "accepts 'no-referrer'" do
        expect do
          ReferrerPolicy.validate_config!("no-referrer")
        end.not_to raise_error
      end

      it "accepts 'no-referrer-when-downgrade'" do
        expect do
          ReferrerPolicy.validate_config!("no-referrer-when-downgrade")
        end.not_to raise_error
      end

      it "accepts 'origin'" do
        expect do
          ReferrerPolicy.validate_config!("origin")
        end.not_to raise_error
      end

      it "accepts 'origin-when-cross-origin'" do
        expect do
          ReferrerPolicy.validate_config!("origin-when-cross-origin")
        end.not_to raise_error
      end

      it "accepts 'unsafe-url'" do
        expect do
          ReferrerPolicy.validate_config!("unsafe-url")
        end.not_to raise_error
      end

      it "accepts nil" do
        expect do
          ReferrerPolicy.validate_config!(nil)
        end.not_to raise_error
      end
    end

    context 'invlaid configuration values' do
      it "doesn't accept invalid values" do
        expect do
          ReferrerPolicy.validate_config!("open")
        end.to raise_error(ReferrerPolicyConfigError)
      end
    end
  end
end
