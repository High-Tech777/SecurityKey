# frozen_string_literal: true

require "test_helper"

module Passkeyed
  class CredentialTest < Minitest::Test
    def setup
      @user = User.create!(email: "owner@example.test")
    end

    def test_valid_credential
      credential = @user.passkeyed_credentials.build(
        external_id: "abc", public_key: "key", sign_count: 0
      )

      assert_predicate credential, :valid?
    end

    def test_requires_external_id
      credential = @user.passkeyed_credentials.build(public_key: "key", sign_count: 0)

      refute_predicate credential, :valid?
      assert_includes credential.errors[:external_id], "can't be blank"
    end

    def test_external_id_is_unique
      @user.passkeyed_credentials.create!(external_id: "dup", public_key: "key", sign_count: 0)
      duplicate = @user.passkeyed_credentials.build(external_id: "dup", public_key: "key2", sign_count: 0)

      refute_predicate duplicate, :valid?
    end

    def test_sign_count_must_be_non_negative
      credential = @user.passkeyed_credentials.build(
        external_id: "neg", public_key: "key", sign_count: -1
      )

      refute_predicate credential, :valid?
    end

    def test_stores_a_large_public_key
      # An RSA COSE key base64s to ~363 chars; the column must be text so it
      # isn't truncated (varchar(255) on MySQL).
      large_key = "k" * 400
      credential = @user.passkeyed_credentials.create!(
        external_id: "rsa", public_key: large_key, sign_count: 0
      )

      assert_equal large_key, credential.reload.public_key
    end

    def test_rejects_an_over_long_nickname
      credential = @user.passkeyed_credentials.build(
        external_id: "nick", public_key: "key", sign_count: 0, nickname: "n" * 256
      )

      refute_predicate credential, :valid?
    end

    def test_allows_a_nil_nickname
      credential = @user.passkeyed_credentials.build(
        external_id: "nonick", public_key: "key", sign_count: 0, nickname: nil
      )

      assert_predicate credential, :valid?
    end

    def test_record_sign_in_advances_count_and_stamps_last_used
      credential = @user.passkeyed_credentials.create!(external_id: "si", public_key: "k", sign_count: 0)

      credential.record_sign_in!(4)

      assert_equal 4, credential.reload.sign_count
      refute_nil credential.last_used_at
    end

    def test_record_sign_in_refreshes_the_backup_state
      credential = @user.passkeyed_credentials.create!(
        external_id: "bs", public_key: "k", sign_count: 0, backed_up: false
      )

      credential.record_sign_in!(1, backed_up: true)

      assert credential.reload.backed_up
    end

    def test_record_sign_in_leaves_the_backup_state_alone_when_not_reported
      credential = @user.passkeyed_credentials.create!(
        external_id: "bs2", public_key: "k", sign_count: 0, backed_up: true
      )

      credential.record_sign_in!(1)

      assert credential.reload.backed_up
    end

    def test_transports_round_trips_as_an_array
      credential = @user.passkeyed_credentials.create!(
        external_id: "tr", public_key: "k", sign_count: 0, transports: %w[internal hybrid]
      )

      assert_equal %w[internal hybrid], credential.reload.transports
    end

    def test_transports_allows_nil
      credential = @user.passkeyed_credentials.create!(
        external_id: "tr2", public_key: "k", sign_count: 0, transports: nil
      )

      assert_nil credential.reload.transports
    end

    def test_record_sign_in_tolerates_a_legacy_invalid_record
      credential = @user.passkeyed_credentials.create!(external_id: "legacy-nick", public_key: "k", sign_count: 0)
      # A nickname persisted before the length cap existed: invalid by today's
      # rules, but it must not start failing every sign-in.
      credential.update_column(:nickname, "n" * 300)

      credential.record_sign_in!(2)

      assert_equal 2, credential.reload.sign_count
    end

    def test_transports_reads_corrupt_stored_data_as_nil
      credential = @user.passkeyed_credentials.create!(external_id: "corrupt", public_key: "k", sign_count: 0)
      credential.update_column(:transports, "not json")

      assert_nil credential.reload.transports
    end

    def test_record_sign_in_works_without_a_last_used_at_column
      # A credentials table as it existed before the last_used_at migration:
      # record_sign_in! must still advance the counter, not raise.
      connection = ActiveRecord::Base.connection
      connection.create_table(:legacy_credentials, force: true) do |t|
        t.references :user, polymorphic: true, null: false
        t.string :external_id, null: false
        t.text :public_key, null: false
        t.bigint :sign_count, null: false, default: 0
        t.timestamps
      end
      legacy_class = Class.new(Passkeyed::Credential) { self.table_name = "legacy_credentials" }
      record = legacy_class.create!(user: @user, external_id: "legacy", public_key: "k", sign_count: 0)

      # backed_up is reported but its column doesn't exist either: also skipped.
      record.record_sign_in!(9, backed_up: true)

      assert_equal 9, record.reload.sign_count
    ensure
      connection&.drop_table(:legacy_credentials, if_exists: true)
    end
  end
end
