# frozen_string_literal: true
require "secure_headers/task_helper"

namespace :secure_headers do
  include SecureHeaders::TaskHelper

  desc "Generate #{SecureHeaders::Configuration::HASH_CONFIG_FILE}"
  task :generate_hashes do |t, args|
    script_hashes = {
      "scripts" => {},
      "styles" => {}
    }

    Dir.glob("app/{views,templates}/**/*.{erb,mustache}") do |filename|
      hashes = generate_inline_script_hashes(filename)
      if hashes.any?
        script_hashes["scripts"][filename] = hashes
      end

      hashes = generate_inline_style_hashes(filename)
      if hashes.any?
        script_hashes["styles"][filename] = hashes
      end
    end

    File.open(SecureHeaders::Configuration::HASH_CONFIG_FILE, "w") do |file|
      file.write(script_hashes.to_yaml)
    end

    puts "Script hashes from " + script_hashes.keys.size.to_s + " files added to #{SecureHeaders::Configuration::HASH_CONFIG_FILE}"
  end
end
