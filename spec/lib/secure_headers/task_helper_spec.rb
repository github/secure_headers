# frozen_string_literal: true
require "spec_helper"
require "secure_headers/task_helper"

class TestHelper
  include SecureHeaders::TaskHelper
end

module SecureHeaders
  describe TaskHelper do
    subject { TestHelper.new }

    let(:template) do
      <<EOT
<html>
  <head>
    <script>alert("Hello World!")</script>
    <style>p { color: red; }</style>
    <%= hashed_javascript_tag do %>
      alert("Using the helper tag!")
    <% end %>
    <%= hashed_style_tag do %>
      p { text-decoration: underline; }
    <% end %>
  </head>
  <body>
    <p>Testing</p>
  </body>
</html>
EOT
    end

    let(:template_unindented) do
      <<EOT
<html>
  <head>
    <script>alert("Hello World!")</script>
    <style>p { color: red; }</style>
    <%= hashed_javascript_tag do %>
      alert("Using the helper tag!")
<% end %>
    <%= hashed_style_tag do %>
      p { text-decoration: underline; }
<% end %>
  </head>
  <body>
    <p>Testing</p>
  </body>
</html>
EOT
    end

    describe "#generate_inline_script_hashes" do
      let(:expected_hashes) do
        [
          "'sha256-EE/znQZ7BcfM3LbsqxUc5JlCtE760Pc2RV18tW90DCo='",
          "'sha256-64ro9ciexeO5JqSZcAnhmJL4wbzCrpsZJLWl5H6mrkA='"
        ]
      end

      it "returns an array of found script hashes" do
        Tempfile.create("script") do |f|
          f.write template
          f.flush
          expect(subject.generate_inline_script_hashes(f.path)).to eq expected_hashes
        end
      end
      it "returns the same array no matter the indentation of helper end tags" do
        Tempfile.create("script") do |f|
          f.write template_unindented
          f.flush
          expect(subject.generate_inline_script_hashes(f.path)).to eq expected_hashes
        end
      end
    end

    describe "#generate_inline_style_hashes" do
      let(:expected_hashes) do
        [
          "'sha256-pckGv9YvNcB5xy+Y4fbqhyo+ib850wyiuWeNbZvLi00='",
          "'sha256-d374zYt40cLTr8J7Cvm/l4oDY4P9UJ8TWhYG0iEglU4='"
        ]
      end

      it "returns an array of found style hashes" do
        Tempfile.create("style") do |f|
          f.write template
          f.flush
          expect(subject.generate_inline_style_hashes(f.path)).to eq expected_hashes
        end
      end
      it "returns the same array no matter the indentation of helper end tags" do
        Tempfile.create("style") do |f|
          f.write template_unindented
          f.flush
          expect(subject.generate_inline_style_hashes(f.path)).to eq expected_hashes
        end
      end
    end

    describe "#dynamic_content?" do
      context "mustache file" do
        it "finds mustache templating tokens" do
          expect(subject.dynamic_content?("file.mustache", "var test = {{ dynamic_value }};")).to be true
        end

        it "returns false when not finding any templating tokens" do
          expect(subject.dynamic_content?("file.mustache", "var test = 'static value';")).to be false
        end
      end

      context "erb file" do
        it "finds erb templating tokens" do
          expect(subject.dynamic_content?("file.erb", "var test = <%= dynamic_value %>;")).to be true
        end

        it "returns false when not finding any templating tokens" do
          expect(subject.dynamic_content?("file.erb", "var test = 'static value';")).to be false
        end
      end
    end
  end
end
