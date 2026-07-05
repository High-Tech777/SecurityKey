# frozen_string_literal: true

module Passkeyed
  # Controller-side helpers for the two WebAuthn ceremonies. Include in a
  # controller (it relies on +session+):
  #
  #   class SessionsController < ApplicationController
  #     include Passkeyed::Ceremonies
  #   end
  #
  # Each ceremony is the same shape: issue a challenge, let the authenticator
  # sign it, verify the signature. The +*_options+ methods stash the challenge
  # in the session; the bang methods consume it and verify.
  #
  # Both bang methods emit an ActiveSupport::Notifications event
  # ("register.passkeyed" / "authenticate.passkeyed") whose payload carries
  # +:credential+ and +:user+ on success and the standard +:exception+ keys on
  # failure — subscribe to observe failed sign-ins, which the success-only
  # after_* hooks never see.
  module Ceremonies
    # Build creation options for a passwordless, discoverable credential and
    # remember the challenge. Render the return value as JSON to the browser.
    def passkey_registration_options(user)
      # Resolve (and, for a pre-existing user, lazily assign) the WebAuthn user
      # handle before building options, so user.id is never nil in the JSON.
      user_handle = user.passkeyed_webauthn_id!

      options = WebAuthn::Credential.options_for_create(
        user: {
          id: user_handle,
          name: user.passkey_name,
          display_name: user.passkey_display_name
        },
        exclude: user.passkeyed_credentials.pluck(:external_id),
        authenticator_selection: {
          resident_key: "required",
          user_verification: Passkeyed.configuration.user_verification
        },
        relying_party: Passkeyed.configuration.relying_party
      )

      stash_challenge(Passkeyed.configuration.registration_challenge_key, options.challenge)
      options
    end

    # Verify a registration response against the stored challenge and persist
    # the new credential. Returns the Passkeyed::Credential, or raises
    # Passkeyed::RegistrationError / ChallengeMissing / ChallengeExpired.
    def passkey_register!(user, credential, nickname: nil)
      record = ActiveSupport::Notifications.instrument("register.passkeyed", user: user) do |payload|
        verify_registration(user, credential, nickname: nickname).tap do |created|
          payload[:credential] = created
        end
      end

      # Outside the instrumented block and the ceremony's rescues, so a raising
      # hook surfaces as itself and doesn't mark the ceremony event as failed.
      after_passkey_registration(record)
      record
    end

    # Build request options for a passwordless sign-in. No allow-list is sent,
    # so the authenticator offers whatever discoverable passkeys it holds for
    # this site. Remembers the challenge; render the return value as JSON.
    def passkey_authentication_options
      options = WebAuthn::Credential.options_for_get(
        user_verification: Passkeyed.configuration.user_verification,
        relying_party: Passkeyed.configuration.relying_party
      )

      stash_challenge(Passkeyed.configuration.authentication_challenge_key, options.challenge)
      options
    end

    # Verify an authentication response. Resolves the credential by its id,
    # checks the signature against the stored public key and challenge, enforces
    # user verification when configured, bumps the signature counter, and
    # returns the owning record. Raises Passkeyed::AuthenticationError /
    # CredentialNotFound / ChallengeMissing / ChallengeExpired.
    def passkey_authenticate!(credential)
      stored = ActiveSupport::Notifications.instrument("authenticate.passkeyed", {}) do |payload|
        verify_authentication(credential).tap do |verified|
          payload[:credential] = verified
          payload[:user] = verified.user
        end
      end

      after_passkey_authentication(stored, stored.user)
      stored.user
    end

    private

    # The registration ceremony proper: consume the challenge, verify the
    # attestation, persist. Kept apart from passkey_register! so its rescues
    # never rewrite an exception raised by the after_* hook.
    def verify_registration(user, credential, nickname: nil)
      challenge = consume_challenge(Passkeyed.configuration.registration_challenge_key, "registration")

      webauthn_credential = parse_credential(:from_create, credential, Passkeyed::RegistrationError)

      # user_verification: true makes webauthn-ruby check the User-Verified flag
      # server-side, which is what actually enforces the configured policy. The
      # value sent to the client is only advisory.
      webauthn_credential.verify(challenge, user_verification: passkeyed_user_verification?)

      user.passkeyed_credentials.create!(
        external_id: webauthn_credential.id,
        public_key: webauthn_credential.public_key,
        sign_count: webauthn_credential.sign_count,
        nickname: nickname.presence,
        **credential_metadata(webauthn_credential)
      )
    rescue WebAuthn::Error => e
      raise Passkeyed::RegistrationError, e.message
    rescue ActiveRecord::RecordNotUnique
      # A check-then-insert race past the uniqueness validation would otherwise
      # escape as a 500. Surface it as a typed "already registered" error.
      raise Passkeyed::RegistrationError, "Credential already registered"
    rescue ActiveRecord::RecordInvalid => e
      # A credential id already on record (a double-submit, or a credential held
      # by another account) is the common validation failure; report it as
      # "already registered". Any other invalidity — e.g. an over-long nickname —
      # surfaces its own message rather than being mislabeled.
      raise Passkeyed::RegistrationError, "Credential already registered" if
        e.record.errors.of_kind?(:external_id, :taken)

      raise Passkeyed::RegistrationError, e.record.errors.full_messages.to_sentence
    end

    # The authentication ceremony proper; see verify_registration for why it is
    # separate from passkey_authenticate!.
    def verify_authentication(credential)
      challenge = consume_challenge(Passkeyed.configuration.authentication_challenge_key, "authentication")

      webauthn_credential = parse_credential(:from_get, credential, Passkeyed::AuthenticationError)

      stored = Passkeyed::Credential.find_by(external_id: webauthn_credential.id)
      # CredentialNotFound is a subclass of AuthenticationError, so a single
      # `rescue Passkeyed::AuthenticationError` collapses both outcomes; do that
      # in your controller and return one generic message to avoid leaking
      # whether a credential id is on record.
      raise Passkeyed::CredentialNotFound, "Unknown credential" unless stored

      # The owner association is polymorphic, so there is no foreign key: a
      # credential can outlive its owner when rows are removed without callbacks
      # (delete/delete_all, raw SQL). Same error and message as an unknown id,
      # so nothing is leaked about the orphan.
      owner = stored.user
      raise Passkeyed::CredentialNotFound, "Unknown credential" if owner.nil?

      # Defense in depth: a discoverable assertion carries the user handle the
      # authenticator stored. When present, it must match the credential's owner;
      # a mismatch means the credential/owner mapping doesn't line up.
      asserted_handle = webauthn_credential.user_handle
      if asserted_handle.present? && owner.webauthn_id != asserted_handle
        raise Passkeyed::AuthenticationError, "Credential does not match its owner"
      end

      webauthn_credential.verify(
        challenge,
        public_key: stored.public_key,
        sign_count: stored.sign_count,
        user_verification: passkeyed_user_verification?
      )

      stored.record_sign_in!(webauthn_credential.sign_count, backed_up: webauthn_credential.backed_up?)
      stored
    rescue WebAuthn::Error => e
      raise Passkeyed::AuthenticationError, e.message
    end

    # Overridable hooks, called after a ceremony succeeds. Defaults are no-ops;
    # override in your controller to audit-log, send a "new device" email, bump a
    # "last used" timestamp, etc. They run with full controller context (request,
    # current_user) and outside the ceremony's error handling, so an exception
    # raised here propagates unchanged rather than becoming a Passkeyed::Error.
    def after_passkey_registration(credential); end

    def after_passkey_authentication(credential, user); end

    # Where challenges are stashed. Defaults to the controller's session;
    # overridable (and easy to stub in tests).
    def passkeyed_session
      session
    end

    # Challenges are stored with their issue time (string keys survive the
    # cookie session's JSON round-trip) so consumption can enforce a lifetime.
    def stash_challenge(key, challenge)
      passkeyed_session[key] = { "challenge" => challenge, "issued_at" => Time.now.to_i }
    end

    # Read-and-delete the stashed challenge: single-use by construction. Raises
    # ChallengeMissing when absent (or not in the expected hash format) and
    # ChallengeExpired when older than the configured challenge_timeout.
    def consume_challenge(key, ceremony)
      stash = passkeyed_session.delete(key)
      challenge = stash["challenge"] if stash.is_a?(Hash)
      raise Passkeyed::ChallengeMissing, "No #{ceremony} challenge in session" if challenge.blank?

      age = Time.now.to_i - stash["issued_at"].to_i
      if age > Passkeyed.configuration.challenge_timeout
        raise Passkeyed::ChallengeExpired, "The #{ceremony} challenge has expired; restart the ceremony"
      end

      challenge
    end

    # Authenticator metadata worth keeping for a credential-management UI:
    # whether the passkey is synced (backed up) or device-bound, how the
    # authenticator talks to clients, and which authenticator model minted it.
    # Each attribute is guarded on its column so apps that trimmed the optional
    # columns from the generated migration keep registering.
    def credential_metadata(webauthn_credential)
      columns = Passkeyed::Credential.column_names
      metadata = {}
      metadata[:backup_eligible] = webauthn_credential.backup_eligible? if columns.include?("backup_eligible")
      metadata[:backed_up] = webauthn_credential.backed_up? if columns.include?("backed_up")
      metadata[:transports] = webauthn_credential.response.transports.presence if columns.include?("transports")
      metadata[:aaguid] = webauthn_credential.response.aaguid if columns.include?("aaguid")
      metadata
    end

    # True when the configured policy demands the User-Verified flag. webauthn-ruby
    # treats a truthy value as "enforce UV".
    def passkeyed_user_verification?
      Passkeyed.configuration.user_verification == "required"
    end

    # Parse a browser credential into a webauthn-ruby object, turning malformed
    # input into a clean Passkeyed error instead of a stray NoMethodError that
    # would surface as a 500. Accepts ActionController::Parameters or a Hash.
    # The parsed credential carries the relying party its later +verify+ checks
    # against, so passkeyed's settings apply without touching webauthn-ruby's
    # global configuration.
    def parse_credential(method, credential, error_class)
      WebAuthn::Credential.public_send(
        method,
        normalize_credential(credential),
        relying_party: Passkeyed.configuration.relying_party
      )
    rescue WebAuthn::Error
      raise
    rescue StandardError
      raise error_class, "Malformed credential"
    end

    # Accept ActionController::Parameters (what `params[:credential]` is) as
    # well as a plain Hash, so callers need not convert by hand.
    def normalize_credential(credential)
      credential.respond_to?(:to_unsafe_h) ? credential.to_unsafe_h : credential
    end
  end
end
