# frozen_string_literal: true

module Passkeyed
  # Base class for every error raised by passkeyed. Rescue this to catch any
  # ceremony failure in one place.
  class Error < StandardError; end

  # Raised when a registration (attestation) ceremony fails verification.
  class RegistrationError < Error; end

  # Raised when an authentication (assertion) ceremony fails verification.
  class AuthenticationError < Error; end

  # Raised during authentication when the asserted credential is not one we
  # have on record.
  class CredentialNotFound < AuthenticationError; end

  # Raised when the server-issued challenge is absent from the session, which
  # usually means the ceremony was started in a different session or the
  # challenge was already consumed.
  class ChallengeMissing < Error; end

  # Raised when the stored challenge is older than the configured
  # +challenge_timeout+. A challenge should be signed within moments of being
  # issued; a stale one usually means a form left open for hours. Subclasses
  # ChallengeMissing because the remedy is identical (restart the ceremony), so
  # one rescue can handle both.
  class ChallengeExpired < ChallengeMissing; end

  # Raised at boot/use time when passkeyed is misconfigured or the host model
  # is missing required schema (e.g. an invalid +user_verification+ value or a
  # missing +webauthn_id+ column). Fails fast rather than degrading silently.
  class ConfigurationError < Error; end
end
