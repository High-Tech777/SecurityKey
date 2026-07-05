# frozen_string_literal: true

require "test_helper"

module Passkeyed
  class ModelTest < Minitest::Test
    def test_assigns_webauthn_id_on_create
      user = User.create!(email: "a@example.test")

      refute_nil user.webauthn_id
      assert_operator user.webauthn_id.length, :>, 0
    end

    def test_does_not_overwrite_an_existing_webauthn_id
      handle = WebAuthn.generate_user_id
      user = User.create!(email: "b@example.test", webauthn_id: handle)

      assert_equal handle, user.webauthn_id
    end

    def test_passkey_name_prefers_email
      user = User.create!(email: "c@example.test")

      assert_equal "c@example.test", user.passkey_name
    end

    def test_passkey_name_falls_back_to_handle
      user = User.create!(email: nil)

      assert_equal user.webauthn_id, user.passkey_name
    end

    def test_passkey_display_name_defaults_to_passkey_name
      user = User.create!(email: "e@example.test")

      assert_equal user.passkey_name, user.passkey_display_name
    end

    def test_credentials_are_destroyed_with_the_owner
      user = User.create!(email: "d@example.test")
      user.passkeyed_credentials.create!(external_id: "x", public_key: "k", sign_count: 0)

      assert_difference -> { Passkeyed::Credential.count }, -1 do
        user.destroy
      end
    end

    def test_rename_passkey_updates_the_nickname
      user = User.create!(email: "rename@example.test")
      credential = user.passkeyed_credentials.create!(external_id: "r", public_key: "k", sign_count: 0)

      user.rename_passkey(credential.id, "Work Laptop")

      assert_equal "Work Laptop", credential.reload.nickname
    end

    def test_rename_passkey_will_not_touch_another_owners_credential
      user = User.create!(email: "owner@example.test")
      other = User.create!(email: "intruder@example.test")
      credential = user.passkeyed_credentials.create!(external_id: "s", public_key: "k", sign_count: 0)

      assert_raises(ActiveRecord::RecordNotFound) do
        other.rename_passkey(credential.id, "hijacked")
      end
    end

    def test_revoke_passkey_deletes_the_credential
      user = User.create!(email: "revoke@example.test")
      credential = user.passkeyed_credentials.create!(external_id: "t", public_key: "k", sign_count: 0)

      assert_difference -> { Passkeyed::Credential.count }, -1 do
        user.revoke_passkey(credential.id)
      end
    end

    def test_revoke_passkey_will_not_touch_another_owners_credential
      user = User.create!(email: "keep@example.test")
      other = User.create!(email: "thief@example.test")
      credential = user.passkeyed_credentials.create!(external_id: "u", public_key: "k", sign_count: 0)

      assert_raises(ActiveRecord::RecordNotFound) do
        other.revoke_passkey(credential.id)
      end
    end

    def test_passkeyed_webauthn_id_assigns_and_persists_when_blank
      user = User.create!(email: "lazy@example.test")
      user.update_column(:webauthn_id, nil)

      handle = user.passkeyed_webauthn_id!

      refute_nil handle
      assert_equal handle, user.reload.webauthn_id
    end

    def test_raises_a_configuration_error_when_the_column_is_missing
      ActiveRecord::Base.connection.create_table(:widgets, force: true) { |t| t.string :name }
      widget_class = Class.new(ActiveRecord::Base) do
        self.table_name = "widgets"
        include Passkeyed::Model
      end

      assert_raises(Passkeyed::ConfigurationError) do
        widget_class.new.passkeyed_webauthn_id!
      end
    ensure
      ActiveRecord::Base.connection.drop_table(:widgets, if_exists: true)
    end

    private

    def assert_difference(callable, delta)
      before = callable.call
      yield

      assert_equal before + delta, callable.call
    end
  end
end
