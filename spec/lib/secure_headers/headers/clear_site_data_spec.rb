# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe ClearSiteData do
    describe "make_header" do
      it "returns nil with nil config" do
        expect(described_class.make_header).to be_nil
      end

      it "returns nil with empty config" do
        expect(described_class.make_header([])).to be_nil
      end

      it "returns nil with opt-out config" do
        expect(described_class.make_header(OPT_OUT)).to be_nil
      end

      it "returns all types with `true` config" do
        name, value = described_class.make_header(true)

        expect(name).to eq(ClearSiteData::HEADER_NAME)
        expect(value).to eq(normalize_json(<<-HERE))
          {
            "types": [
              "cache",
              "cookies",
              "storage",
              "executionContexts"
            ]
          }
        HERE
      end

      it "returns specified types" do
        name, value = described_class.make_header(["foo", "bar"])

        expect(name).to eq(ClearSiteData::HEADER_NAME)
        expect(value).to eq(normalize_json(<<-HERE))
          {
            "types": [
              "foo",
              "bar"
            ]
          }
        HERE
      end
    end

    describe "validate_config!" do
      it "succeeds for `true` config" do
        expect do
          described_class.validate_config!(true)
        end.not_to raise_error
      end

      it "succeeds for `nil` config" do
        expect do
          described_class.validate_config!(nil)
        end.not_to raise_error
      end

      it "succeeds for opt-out config" do
        expect do
          described_class.validate_config!(OPT_OUT)
        end.not_to raise_error
      end

      it "succeeds for empty config" do
        expect do
          described_class.validate_config!([])
        end.not_to raise_error
      end

      it "succeeds for Array of Strings config" do
        expect do
          described_class.validate_config!(["foo"])
        end.not_to raise_error
      end

      it "fails for Array of non-String config" do
        expect do
          described_class.validate_config!([1])
        end.to raise_error(ClearSiteDataConfigError)
      end

      it "fails for non-serializable config" do
        expect do
          described_class.validate_config!(["hi \255"])
        end.to raise_error(ClearSiteDataConfigError)
      end

      it "fails for other types of config" do
        expect do
          described_class.validate_config!(:cookies)
        end.to raise_error(ClearSiteDataConfigError)
      end
    end

    def normalize_json(json)
      JSON.dump(JSON.parse(json))
    end
  end
end
