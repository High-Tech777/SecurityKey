# frozen_string_literal: true

module Passkeyed
  # Holds passkeyed's settings. The relevant ones are handed to webauthn-ruby
  # as an isolated WebAuthn::RelyingParty (see +relying_party+), never written
  # to WebAuthn's global configuration.
  #
  #   Passkeyed.configure do |config|
  #     config.rp_name          = "Acme"
  #     config.rp_id            = "acme.example"           # optional
  #     config.allowed_origins  = ["https://acme.example"] # required when deployed
  #     config.user_verification = "required"
  #   end
  class Configuration
    # The WebAuthn userVerification enum. We normalize to these exact strings so
    # the value advertised to the client and the value enforced server-side can
    # never diverge (a symbol or mis-cased string would silently disable
    # enforcement while still advertising "required").
    USER_VERIFICATION_LEVELS = %w[required preferred discouraged].freeze

    # Human-readable name of the relying party (your app), shown by some
    # authenticators during the ceremony.
    attr_accessor :rp_name

    # The relying party id (effectively your domain). When nil, webauthn-ruby
    # derives it from the request origin.
    attr_accessor :rp_id

    # Array of origins the server will accept assertions from, e.g.
    # ["https://acme.example"]. Left nil only for local development; required
    # (https-only) in any deployed environment — see +validate!+.
    attr_accessor :allowed_origins

    # User-verification requirement for both ceremonies. "required" is what
    # makes a single passkey gesture genuinely multi-factor. Read via the
    # accessor; always one of USER_VERIFICATION_LEVELS (see the writer).
    attr_reader :user_verification

    # Base session key from which the per-ceremony challenge keys are derived
    # (see +registration_challenge_key+ / +authentication_challenge_key+).
    attr_accessor :session_key

    # How long (in seconds) a stashed challenge stays valid. A ceremony should
    # complete within moments; a challenge consumed hours after it was issued
    # points at a stale tab or a replay attempt, so it is rejected with
    # Passkeyed::ChallengeExpired. Also advertised to the browser as the
    # ceremony timeout (via the relying party), so the credential prompt and
    # the server agree on the lifetime. Read via the accessor; always a
    # positive Integer (see the writer).
    attr_reader :challenge_timeout

    def initialize
      @rp_name = "Passkeyed"
      @rp_id = nil
      @allowed_origins = nil
      self.user_verification = "required"
      @session_key = :passkeyed_challenge
      self.challenge_timeout = 300
    end

    # Normalize and validate on assignment so that, e.g., +:required+ (symbol)
    # or "Required" can't slip through as a value that is advertised to the
    # client but not enforced by +verify+. Raises on anything outside the enum.
    def user_verification=(value)
      normalized = value.to_s.downcase
      unless USER_VERIFICATION_LEVELS.include?(normalized)
        raise Passkeyed::ConfigurationError,
              "user_verification must be one of #{USER_VERIFICATION_LEVELS.join(", ")}; got #{value.inspect}"
      end

      @user_verification = normalized
    end

    # Validate on assignment so a nonsensical timeout (zero, negative, "5m")
    # fails at boot rather than expiring every challenge or none.
    def challenge_timeout=(value)
      seconds = begin
        Integer(value)
      rescue TypeError, ArgumentError
        raise Passkeyed::ConfigurationError,
              "challenge_timeout must be a positive number of seconds; got #{value.inspect}"
      end

      unless seconds.positive?
        raise Passkeyed::ConfigurationError,
              "challenge_timeout must be a positive number of seconds; got #{value.inspect}"
      end

      @challenge_timeout = seconds
    end

    # Distinct session keys for the two ceremonies, derived from +session_key+.
    # Keeping them separate means a registration and an authentication ceremony
    # running concurrently in the same session (a background tab, a stale form)
    # can't overwrite each other's single-use challenge.
    def registration_challenge_key
      :"#{session_key}_registration"
    end

    def authentication_challenge_key
      :"#{session_key}_authentication"
    end

    # The WebAuthn::RelyingParty these settings describe, passed explicitly to
    # every webauthn-ruby entry point. Keeping it off WebAuthn's global
    # configuration means a host app (or another gem) using webauthn-ruby
    # directly is never clobbered. Built fresh on each call — the object is
    # cheap, and this way later configuration writes are always reflected.
    def relying_party
      WebAuthn::RelyingParty.new(
        name: rp_name,
        id: rp_id,
        allowed_origins: allowed_origins,
        # Also advertised to the browser as the ceremony timeout, so the
        # credential prompt can't outlive the server-side challenge.
        credential_options_timeout: challenge_timeout * 1000
      )
    end

    # Refuse to boot a deployed app with development origins. WebAuthn requires
    # a secure context, so a blank allow-list or an http:// origin outside
    # development and test is always a misconfiguration — most often the
    # generated localhost default left in place. Fail loud at boot rather than
    # silently rejecting every sign-in (or, worse, trusting an insecure
    # origin). Runs in every non-local environment (production, staging, any
    # custom deploy env); no-op in development/test and when Rails isn't
    # loaded (e.g. the gem's own suite).
    def validate!
      return unless enforce_secure_origins?

      if allowed_origins.blank?
        raise Passkeyed::ConfigurationError,
              "allowed_origins is required outside development and test; " \
              "set config.allowed_origins to your HTTPS origin(s)"
      end

      insecure = allowed_origins.reject { |origin| origin.to_s.start_with?("https://") }
      return if insecure.empty?

      raise Passkeyed::ConfigurationError,
            "allowed_origins must use https outside development and test; got #{insecure.inspect} " \
            "(the generated localhost default cannot be used in a deployed environment)"
    end

    private

    # True in any deployed environment: everything except Rails.env.local?
    # (development and test, per Rails >= 7.1 — the gem's declared floor).
    def enforce_secure_origins?
      defined?(Rails) && Rails.respond_to?(:env) && !Rails.env.local?
    end
  end

  class << self
    # The ActiveRecord base class Passkeyed::Credential inherits from. Defaults
    # to the host app's ApplicationRecord when defined (so multi-database
    # connects_to/role config is inherited), falling back to ActiveRecord::Base.
    # Set in an initializer to override. Accepts a class or a class name string.
    #
    # Ordering matters: the parent class is resolved once, when Credential is
    # first autoloaded, so assign this before anything references
    # Passkeyed::Credential (an initializer is early enough; a later assignment
    # is silently ignored).
    def base_record_class
      klass = @base_record_class || (defined?(ApplicationRecord) ? ApplicationRecord : ActiveRecord::Base)
      klass.is_a?(String) ? klass.constantize : klass
    end

    attr_writer :base_record_class

    def configuration
      @configuration ||= Configuration.new
    end

    # Yields the configuration for editing, then validates it. Call once during
    # boot (an initializer).
    def configure
      yield(configuration) if block_given?
      configuration.validate!
      configuration
    end

    # Mainly for tests: forget all configuration.
    def reset_configuration!
      @configuration = Configuration.new
    end
  end
end
