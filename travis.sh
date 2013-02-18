#! /bin/sh

bundle install >> /dev/null &&
bundle exec rspec --format progress spec &&
cd fixtures/rails_3_2_12 &&
bundle install >> /dev/null &&
bundle exec rspec --format progress spec &&
cd ../../fixtures/rails_3_2_12_no_init &&
bundle install >> /dev/null &&
bundle exec rspec spec