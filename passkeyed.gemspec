# frozen_string_literal: true

require_relative "lib/passkeyed/version"

Gem::Specification.new do |spec|
  spec.name = "passkeyed"
  spec.version = Passkeyed::VERSION
  spec.authors = ["Paul Ardeleanu"]
  spec.email = ["pardel@gmail.com"]

  spec.summary = "Passwordless passkey (WebAuthn) authentication for Rails."
  spec.description = <<~DESC.strip
    passkeyed adds passwordless, usernameless passkey sign-in to Rails apps:
    a small, transparent runtime (a model concern, a controller concern, and a
    Stimulus controller) plus an install generator, built on webauthn-ruby.
  DESC
  spec.homepage = "https://github.com/pardel/passkeyed"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"

  # homepage comes from spec.homepage; keep the other links distinct so
  # rubygems.org renders Homepage / Source Code / Report Issues / Documentation.
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "https://rubydoc.info/gems/passkeyed"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*",
    "sig/**/*",
    "README.md",
    "LICENSE.txt"
  ]
  spec.require_paths = ["lib"]

  spec.add_dependency "activerecord", ">= 7.1"
  spec.add_dependency "activesupport", ">= 7.1"
  spec.add_dependency "railties", ">= 7.1"
  # 3.4 introduced allowed_origins (on both the global config and
  # WebAuthn::RelyingParty), which passkeyed depends on.
  spec.add_dependency "webauthn", ">= 3.4"

  spec.add_development_dependency "minitest", ">= 5.0"
  spec.add_development_dependency "rake", ">= 13.0"
  spec.add_development_dependency "rubocop", ">= 1.60"
  spec.add_development_dependency "rubocop-minitest", ">= 0.34"
  spec.add_development_dependency "rubocop-rake", ">= 0.6"
  spec.add_development_dependency "sqlite3", ">= 1.6"
end
