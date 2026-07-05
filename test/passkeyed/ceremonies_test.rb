# frozen_string_literal: true

require "test_helper"

module Passkeyed
  class CeremoniesTest < Minitest::Test
    include CeremonyHelpers

    def setup
      @controller = FakeController.new
      @user = User.create!(email: "ceremony@example.test")
    end

    # --- registration --------------------------------------------------------

    def test_registration_options_stash_a_challenge
      options = @controller.passkey_registration_options(@user)

      refute_nil options.challenge
      # Stored with its issue time so consumption can enforce a lifetime.
      assert_equal options.challenge, @controller.session[registration_key]["challenge"]
      assert_in_delta Time.now.to_i, @controller.session[registration_key]["issued_at"], 5
    end

    def test_registration_persists_a_credential
      credential = register_passkey(@controller, @user, nickname: "Laptop")

      assert_predicate credential, :persisted?
      assert_equal "Laptop", credential.nickname
      assert_equal 1, @user.passkeyed_credentials.count
      # The challenge is single-use and must be consumed.
      assert_nil @controller.session[registration_key]
    end

    def test_registration_without_a_challenge_raises
      assert_raises(Passkeyed::ChallengeMissing) do
        @controller.passkey_register!(@user, {})
      end
    end

    def test_registration_rejects_an_unverified_user
      # user_verification is "required", so an attestation with UV=0 must fail.
      assert_raises(Passkeyed::RegistrationError) do
        register_passkey(@controller, @user, user_verified: false)
      end
      assert_equal 0, @user.passkeyed_credentials.count
    end

    def test_registration_rejects_a_malformed_credential
      @controller.passkey_registration_options(@user)

      assert_raises(Passkeyed::RegistrationError) do
        @controller.passkey_register!(@user, { "junk" => 1 })
      end
    end

    # --- authentication ------------------------------------------------------

    def test_authentication_round_trip_returns_the_user
      register_passkey(@controller, @user)

      authenticated = authenticate

      assert_equal @user.id, authenticated.id
    end

    def test_authentication_consumes_the_challenge
      register_passkey(@controller, @user)

      options = @controller.passkey_authentication_options
      assertion = fake_client.get(challenge: options.challenge, user_verified: true)
      @controller.passkey_authenticate!(assertion)

      # Challenge is gone, so replaying the same assertion is rejected.
      assert_nil @controller.session[authentication_key]
      assert_raises(Passkeyed::ChallengeMissing) do
        @controller.passkey_authenticate!(assertion)
      end
    end

    def test_authentication_without_a_challenge_raises
      register_passkey(@controller, @user)

      assert_raises(Passkeyed::ChallengeMissing) do
        @controller.passkey_authenticate!({})
      end
    end

    def test_authentication_rejects_an_unverified_user
      register_passkey(@controller, @user)

      assert_raises(Passkeyed::AuthenticationError) do
        authenticate(user_verified: false)
      end
    end

    def test_authentication_persists_the_new_sign_count
      credential = register_passkey(@controller, @user)

      authenticate(sign_count: 7)

      # The stored counter is updated to the value the authenticator asserted,
      # which proves passkey_authenticate! actually persists it.
      assert_equal 7, credential.reload.sign_count
      # ...and a successful assertion stamps last_used_at.
      refute_nil credential.last_used_at
    end

    def test_authentication_rejects_a_regressed_sign_count
      register_passkey(@controller, @user)

      # Move the stored counter forward...
      authenticate(sign_count: 5)
      # ...then present an older counter: the hallmark of a cloned authenticator.
      assert_raises(Passkeyed::AuthenticationError) do
        authenticate(sign_count: 3)
      end
    end

    def test_authentication_with_an_unknown_credential_raises
      register_passkey(@controller, @user)

      other_device = WebAuthn::FakeClient.new(TEST_ORIGIN)
      throwaway = @controller.passkey_registration_options(@user)
      other_device.create(challenge: throwaway.challenge, user_verified: true)

      options = @controller.passkey_authentication_options
      assertion = other_device.get(challenge: options.challenge, user_verified: true)

      assert_raises(Passkeyed::CredentialNotFound) do
        @controller.passkey_authenticate!(assertion)
      end
    end

    def test_authentication_with_an_orphaned_credential_raises
      register_passkey(@controller, @user)

      # Remove the owner without callbacks (as delete_all or raw SQL would):
      # the credential row survives but its user is gone. Must be the same
      # typed error as an unknown id, not a NoMethodError 500.
      @user.delete

      assert_raises(Passkeyed::CredentialNotFound) { authenticate }
    end

    def test_authentication_with_a_tampered_challenge_raises
      register_passkey(@controller, @user)

      @controller.passkey_authentication_options
      # Sign a different challenge than the one the server stored.
      assertion = fake_client.get(challenge: WebAuthn.generate_user_id, user_verified: true)

      assert_raises(Passkeyed::AuthenticationError) do
        @controller.passkey_authenticate!(assertion)
      end
    end

    def test_authentication_with_a_malformed_credential_raises
      register_passkey(@controller, @user)

      @controller.passkey_authentication_options
      assert_raises(Passkeyed::AuthenticationError) do
        @controller.passkey_authenticate!({ "junk" => 1 })
      end
    end

    # --- hardening ------------------------------------------------------------

    def test_registration_backfills_a_missing_webauthn_id
      # Simulate a user that existed before passkeyed was installed.
      @user.update_column(:webauthn_id, nil)

      options = @controller.passkey_registration_options(@user)

      refute_nil @user.reload.webauthn_id
      assert_equal @user.webauthn_id, options.user.id
    end

    def test_registration_excludes_already_registered_credentials
      credential = register_passkey(@controller, @user)

      options = @controller.passkey_registration_options(@user)
      excluded_ids = options.exclude_credentials.map { |descriptor| descriptor[:id] }

      assert_includes excluded_ids, credential.external_id
    end

    def test_registration_translates_a_duplicate_into_a_registration_error
      options = @controller.passkey_registration_options(@user)
      raw = fake_client.create(challenge: options.challenge, user_verified: true)
      external_id = WebAuthn::Credential.from_create(raw).id

      # Pre-seed a clashing credential (as if another account already held it) so
      # create! trips the uniqueness constraint instead of leaking a raw 500.
      other = User.create!(email: "holder@example.test")
      other.passkeyed_credentials.create!(external_id: external_id, public_key: "k", sign_count: 0)

      assert_raises(Passkeyed::RegistrationError) do
        @controller.passkey_register!(@user, raw)
      end
    end

    def test_registration_reports_an_over_long_nickname_clearly
      options = @controller.passkey_registration_options(@user)
      raw = fake_client.create(challenge: options.challenge, user_verified: true)

      error = assert_raises(Passkeyed::RegistrationError) do
        @controller.passkey_register!(@user, raw, nickname: "n" * 256)
      end
      # Not mislabeled as a duplicate; the message names the real problem.
      assert_match(/nickname/i, error.message)
      assert_equal 0, @user.passkeyed_credentials.count
    end

    def test_registration_accepts_action_controller_parameters
      options = @controller.passkey_registration_options(@user)
      raw = fake_client.create(challenge: options.challenge, user_verified: true)

      credential = @controller.passkey_register!(@user, FakeParams.new(raw))

      assert_predicate credential, :persisted?
    end

    def test_authentication_resolves_a_multi_credential_user
      register_passkey(@controller, @user) # device 1

      second_device = WebAuthn::FakeClient.new(TEST_ORIGIN)
      opts = @controller.passkey_registration_options(@user)
      raw = second_device.create(challenge: opts.challenge, user_verified: true)
      @controller.passkey_register!(@user, raw) # device 2

      options = @controller.passkey_authentication_options
      assertion = second_device.get(challenge: options.challenge, user_verified: true)

      assert_equal @user.id, @controller.passkey_authenticate!(assertion).id
    end

    def test_authentication_accepts_a_matching_user_handle
      register_passkey(@controller, @user)

      options = @controller.passkey_authentication_options
      assertion = fake_client.get(
        challenge: options.challenge,
        user_verified: true,
        user_handle: webauthn_encoder.decode(@user.webauthn_id)
      )

      assert_equal @user.id, @controller.passkey_authenticate!(assertion).id
    end

    def test_authentication_rejects_a_mismatched_user_handle
      register_passkey(@controller, @user)

      options = @controller.passkey_authentication_options
      assertion = fake_client.get(
        challenge: options.challenge,
        user_verified: true,
        user_handle: webauthn_encoder.decode(WebAuthn.generate_user_id)
      )

      assert_raises(Passkeyed::AuthenticationError) do
        @controller.passkey_authenticate!(assertion)
      end
    end

    def test_registration_and_authentication_challenges_do_not_collide
      register_passkey(@controller, @user)

      # Start both ceremonies before finishing either, as concurrent tabs would.
      @controller.passkey_authentication_options
      reg_options = @controller.passkey_registration_options(@user)

      # The registration challenge survived starting authentication...
      raw = fake_client.create(challenge: reg_options.challenge, user_verified: true)
      credential = @controller.passkey_register!(@user, raw)

      assert_predicate credential, :persisted?
      # ...and the authentication challenge is still there to be consumed.
      refute_nil @controller.session[authentication_key]
    end

    # --- challenge lifetime ---------------------------------------------------

    def test_an_expired_registration_challenge_raises
      options = @controller.passkey_registration_options(@user)
      age_stashed_challenge(registration_key)
      raw = fake_client.create(challenge: options.challenge, user_verified: true)

      assert_raises(Passkeyed::ChallengeExpired) do
        @controller.passkey_register!(@user, raw)
      end
      # The stale challenge was still consumed: single-use even when rejected.
      assert_nil @controller.session[registration_key]
    end

    def test_an_expired_authentication_challenge_raises
      register_passkey(@controller, @user)

      options = @controller.passkey_authentication_options
      age_stashed_challenge(authentication_key)
      assertion = fake_client.get(challenge: options.challenge, user_verified: true)

      assert_raises(Passkeyed::ChallengeExpired) do
        @controller.passkey_authenticate!(assertion)
      end
    end

    def test_a_plain_string_challenge_stash_counts_as_missing
      register_passkey(@controller, @user)

      options = @controller.passkey_authentication_options
      # A stash that is a bare string rather than the expected hash (tampered
      # or stale session data) must be rejected, not crash consumption.
      @controller.session[authentication_key] = options.challenge
      assertion = fake_client.get(challenge: options.challenge, user_verified: true)

      assert_raises(Passkeyed::ChallengeMissing) do
        @controller.passkey_authenticate!(assertion)
      end
    end

    # --- credential metadata ---------------------------------------------------

    def test_registration_stores_the_backup_flags
      options = @controller.passkey_registration_options(@user)
      raw = fake_client.create(
        challenge: options.challenge,
        user_verified: true,
        backup_eligibility: true,
        backup_state: true
      )

      credential = @controller.passkey_register!(@user, raw)

      assert credential.backup_eligible
      assert credential.backed_up
    end

    def test_registration_stores_the_aaguid_and_transports
      credential = register_passkey(@controller, @user)

      refute_nil credential.aaguid
      # Stored as JSON, read back as the Array the authenticator reported.
      assert_equal ["internal"], credential.reload.transports
    end

    def test_authentication_refreshes_the_backup_state
      options = @controller.passkey_registration_options(@user)
      raw = fake_client.create(
        challenge: options.challenge,
        user_verified: true,
        backup_eligibility: true,
        backup_state: false
      )
      credential = @controller.passkey_register!(@user, raw)

      # The same passkey later reports BS=1: it started syncing.
      auth_options = @controller.passkey_authentication_options
      assertion = fake_client.get(
        challenge: auth_options.challenge,
        user_verified: true,
        backup_eligibility: true,
        backup_state: true
      )
      @controller.passkey_authenticate!(assertion)

      assert credential.reload.backed_up
    end

    # --- instrumentation -------------------------------------------------------

    def test_registration_emits_an_instrumentation_event
      events = subscribe_to("register.passkeyed") do
        register_passkey(@controller, @user)
      end

      assert_equal 1, events.length
      payload = events.first.payload

      assert_equal @user.id, payload[:user].id
      assert_equal @user.passkeyed_credentials.first.id, payload[:credential].id
    end

    def test_authentication_emits_an_instrumentation_event
      register_passkey(@controller, @user)

      events = subscribe_to("authenticate.passkeyed") { authenticate }
      payload = events.first.payload

      assert_equal @user.id, payload[:user].id
    end

    def test_a_failed_authentication_records_the_exception_in_the_event
      register_passkey(@controller, @user)

      events = subscribe_to("authenticate.passkeyed") do
        assert_raises(Passkeyed::AuthenticationError) { authenticate(user_verified: false) }
      end
      payload = events.first.payload

      assert_equal "Passkeyed::AuthenticationError", payload[:exception].first
      assert_nil payload[:user]
    end

    # --- user entity -----------------------------------------------------------

    def test_registration_options_carry_the_display_name
      options = @controller.passkey_registration_options(@user)

      assert_equal @user.passkey_display_name, options.user.display_name
      assert_equal @user.email, options.user.name
    end

    # --- user-verification policy --------------------------------------------

    def test_preferred_uv_does_not_enforce_verification
      with_user_verification("preferred") do
        # UV isn't enforced, so a UV=0 registration and sign-in round-trip.
        register_passkey(@controller, @user, user_verified: false)

        assert_equal @user.id, authenticate(user_verified: false).id
      end
    end

    def test_discouraged_uv_does_not_enforce_verification
      with_user_verification("discouraged") do
        register_passkey(@controller, @user, user_verified: false)

        assert_equal @user.id, authenticate(user_verified: false).id
      end
    end

    # --- hooks ---------------------------------------------------------------

    def test_after_registration_hook_receives_the_credential
      controller = HookedController.new
      credential = register_passkey(controller, @user)

      assert_equal [credential], controller.registered
    end

    def test_after_authentication_hook_receives_the_credential_and_user
      controller = HookedController.new
      register_passkey(controller, @user)

      options = controller.passkey_authentication_options
      assertion = fake_client.get(challenge: options.challenge, user_verified: true)
      controller.passkey_authenticate!(assertion)

      credential, user = controller.authenticated

      assert_equal @user.id, user.id
      assert_equal user.passkeyed_credentials.first.id, credential.id
    end

    private

    # Run a block with a temporary user_verification policy, restoring it after.
    def with_user_verification(level)
      original = Passkeyed.configuration.user_verification
      Passkeyed.configuration.user_verification = level
      yield
    ensure
      Passkeyed.configuration.user_verification = original
    end

    # Backdate a stashed challenge past the configured lifetime.
    def age_stashed_challenge(key)
      stash = @controller.session[key]
      stash["issued_at"] = Time.now.to_i - Passkeyed.configuration.challenge_timeout - 1
    end

    # Collect the ActiveSupport::Notifications events named +name+ emitted while
    # the block runs.
    def subscribe_to(name)
      events = []
      subscription = ActiveSupport::Notifications.subscribe(name) do |event|
        events << event
      end
      yield
      events
    ensure
      ActiveSupport::Notifications.unsubscribe(subscription)
    end

    def registration_key
      Passkeyed.configuration.registration_challenge_key
    end

    def authentication_key
      Passkeyed.configuration.authentication_challenge_key
    end

    # The encoder webauthn-ruby uses for the user handle (base64url). Used to
    # feed FakeClient the raw bytes a real browser would derive from user.id.
    def webauthn_encoder
      WebAuthn.configuration.encoder
    end

    # Drive one authentication ceremony through the controller and return its
    # result. sign_count: nil lets the fake authenticator manage its own counter.
    def authenticate(user_verified: true, sign_count: nil)
      options = @controller.passkey_authentication_options
      assertion = fake_client.get(
        challenge: options.challenge,
        user_verified: user_verified,
        sign_count: sign_count
      )
      @controller.passkey_authenticate!(assertion)
    end
  end
end
