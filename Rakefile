# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test" << "lib"
  t.pattern = "test/**/*_test.rb"
  t.warning = false
end

default_tasks = [:test]

begin
  require "rubocop/rake_task"
  RuboCop::RakeTask.new
  default_tasks << :rubocop
rescue LoadError
  # RuboCop isn't installed (e.g. runtime-only environment); run tests only.
end

task default: default_tasks
