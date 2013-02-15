#! /bin/sh

bundle install
bundle exec rspec spec
cd fixtures/rails_3_2_12
bundle install
bundle exec rspec spec
cd fixtures/rails_3_2_12_no_init
bundle install
bundle exec rspec spec