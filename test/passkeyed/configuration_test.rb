# frozen_string_literal: true

require "test_helper"

module Passkeyed
  class ConfigurationTest < Minitest::Test
    def teardown
      # Restore the suite-wide configuration after any local mutation.
      Passkeyed.configure do |config|
        config.rp_name = "Test RP"
        config.rp_id = "example.test"
        config.allowed_origins = [TEST_ORIGIN]
        config.user_verification = "required"
      end
    end

    def test_defaults
      Passkeyed.reset_configuration!
      config = Passkeyed.configuration

      assert_equal "Passkeyed", config.rp_name
      assert_nil config.rp_id
      assert_nil config.allowed_origins
      assert_equal "required", config.user_verification
      assert_equal :passkeyed_challenge, config.session_key
      assert_equal 300, config.challenge_timeout
    ensure
      teardown
    end

    def test_configure_leaves_webauthn_global_configuration_alone
      Passkeyed.configure do |config|
        config.rp_name = "Acme"
        config.rp_id = "acme.test"
        config.allowed_origins = ["https://acme.test"]
      end

      # passkeyed hands webauthn-ruby an isolated RelyingParty instead, so a
      # host app using webauthn-ruby directly keeps its own settings — the
      # globals stay at webauthn-ruby's untouched defaults (nil).
      assert_nil WebAuthn.configuration.rp_name
      assert_nil WebAuthn.configuration.allowed_origins
    end

    def test_relying_party_reflects_the_configuration
      config = Passkeyed::Configuration.new
      config.rp_name = "Acme"
      config.rp_id = "acme.test"
      config.allowed_origins = ["https://acme.test"]
      config.challenge_timeout = 60

      relying_party = config.relying_party

      assert_kind_of WebAuthn::RelyingParty, relying_party
      assert_equal "Acme", relying_party.name
      assert_equal "acme.test", relying_party.id
      assert_equal ["https://acme.test"], relying_party.allowed_origins
      # The browser is advertised the same lifetime the server enforces (ms).
      assert_equal 60_000, relying_party.credential_options_timeout
    end

    def test_relying_party_reflects_later_configuration_writes
      config = Passkeyed::Configuration.new
      config.rp_name = "Before"
      config.relying_party
      config.rp_name = "After"

      assert_equal "After", config.relying_party.name
    end

    def test_user_verification_normalizes_a_symbol
      Passkeyed.configuration.user_verification = :required

      # Normalized to the string the enforcement check compares against, so a
      # symbol can't advertise "required" while silently skipping enforcement.
      assert_equal "required", Passkeyed.configuration.user_verification
    end

    def test_user_verification_normalizes_case
      Passkeyed.configuration.user_verification = "Required"

      assert_equal "required", Passkeyed.configuration.user_verification
    end

    def test_user_verification_rejects_an_unknown_value
      assert_raises(Passkeyed::ConfigurationError) do
        Passkeyed.configuration.user_verification = "sometimes"
      end
    end

    def test_challenge_timeout_accepts_an_integer_like_value
      config = Passkeyed::Configuration.new
      config.challenge_timeout = "600"

      assert_equal 600, config.challenge_timeout
    end

    def test_challenge_timeout_rejects_a_non_positive_value
      config = Passkeyed::Configuration.new

      assert_raises(Passkeyed::ConfigurationError) { config.challenge_timeout = 0 }
      assert_raises(Passkeyed::ConfigurationError) { config.challenge_timeout = -5 }
    end

    def test_challenge_timeout_rejects_a_non_numeric_value
      config = Passkeyed::Configuration.new

      assert_raises(Passkeyed::ConfigurationError) { config.challenge_timeout = "5 minutes" }
      assert_raises(Passkeyed::ConfigurationError) { config.challenge_timeout = nil }
    end

    def test_base_record_class_defaults_to_active_record_base
      # ApplicationRecord isn't defined in the gem's own suite.
      assert_equal ActiveRecord::Base, Passkeyed.base_record_class
    end

    # --- deployed-environment guard -------------------------------------------

    def test_validate_is_a_no_op_in_the_gem_suite
      config = Passkeyed::Configuration.new
      config.allowed_origins = nil

      # Either Rails isn't loaded at all, or (when another test file pulled in
      # railties) RAILS_ENV is unset and defaults to development — local either
      # way, so the guard stays quiet.
      assert_nil config.validate!
    end

    def test_validate_is_a_no_op_in_development
      with_rails_env("development") do
        config = Passkeyed::Configuration.new
        config.allowed_origins = ["http://localhost:3000"]

        assert_nil config.validate!
      end
    end

    def test_validate_rejects_blank_origins_in_production
      with_rails_env("production") do
        config = Passkeyed::Configuration.new
        config.allowed_origins = nil

        assert_raises(Passkeyed::ConfigurationError) { config.validate! }
      end
    end

    def test_validate_rejects_insecure_origins_in_staging
      # Not just literal production: any non-local env (staging, preview, a
      # custom deploy name) must refuse development origins.
      with_rails_env("staging") do
        config = Passkeyed::Configuration.new
        config.allowed_origins = ["http://localhost:3000"]

        assert_raises(Passkeyed::ConfigurationError) { config.validate! }
      end
    end

    def test_validate_accepts_https_origins_in_production
      with_rails_env("production") do
        config = Passkeyed::Configuration.new
        config.allowed_origins = ["https://acme.example"]

        assert_nil config.validate!
      end
    end

    private

    # Install a minimal top-level Rails whose env is +name+ for the block's
    # duration, so the guard sees a deployed (or local) app without loading
    # Rails proper. Restores whatever Rails constant existed before.
    def with_rails_env(name)
      previous = defined?(Rails) ? Rails : nil
      Object.send(:remove_const, :Rails) if previous

      env = ActiveSupport::EnvironmentInquirer.new(name)
      stub = Module.new
      stub.define_singleton_method(:env) { env }
      Object.const_set(:Rails, stub)
      yield
    ensure
      Object.send(:remove_const, :Rails)
      Object.const_set(:Rails, previous) if previous
    end
  end
end
