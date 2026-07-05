# frozen_string_literal: true

require "minitest/autorun"
require "active_record"
require "webauthn"
require "webauthn/fake_client"
require "passkeyed"

# A fixed relying-party origin used across the suite. WebAuthn::FakeClient is
# bound to this origin and the configuration trusts it.
TEST_ORIGIN = "https://example.test"

Passkeyed.configure do |config|
  config.rp_name = "Test RP"
  config.rp_id = "example.test"
  config.allowed_origins = [TEST_ORIGIN]
  config.user_verification = "required"
end

ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
ActiveRecord::Schema.verbose = false
ActiveRecord::Schema.define do
  create_table :users do |t|
    t.string :email
    t.string :webauthn_id
    t.timestamps
  end
  add_index :users, :webauthn_id, unique: true

  create_table :passkeyed_credentials do |t|
    t.references :user, polymorphic: true, null: false
    t.string :external_id, null: false
    t.text :public_key, null: false
    t.bigint :sign_count, null: false, default: 0
    t.string :nickname
    t.datetime :last_used_at
    t.boolean :backup_eligible
    t.boolean :backed_up
    t.string :transports
    t.string :aaguid
    t.timestamps
  end
  add_index :passkeyed_credentials, :external_id, unique: true
end

# The owner model under test.
class User < ActiveRecord::Base
  include Passkeyed::Model
end

# A minimal stand-in for a Rails controller: the ceremony concern only needs a
# +session+, which here is a plain Hash.
class FakeController
  include Passkeyed::Ceremonies

  attr_reader :session

  def initialize
    @session = {}
  end
end

# A controller that overrides the ceremony hooks to record their arguments, so
# tests can assert the hooks fire with the right objects.
class HookedController < FakeController
  attr_reader :registered, :authenticated

  private

  def after_passkey_registration(credential)
    @registered = [credential]
  end

  def after_passkey_authentication(credential, user)
    @authenticated = [credential, user]
  end
end

# Stands in for ActionController::Parameters (which isn't a gem dependency):
# exercises the +normalize_credential+ +to_unsafe_h+ branch without actionpack.
class FakeParams
  def initialize(hash)
    @hash = hash
  end

  def to_unsafe_h
    @hash
  end
end

module CeremonyHelpers
  # A WebAuthn::FakeClient bound to the trusted origin.
  def fake_client
    @fake_client ||= WebAuthn::FakeClient.new(TEST_ORIGIN)
  end

  # Run a full registration ceremony for +user+ via +controller+ and return the
  # created Passkeyed::Credential. user_verified defaults to true to model a
  # platform authenticator (Touch ID / Windows Hello) that did a UV gesture.
  def register_passkey(controller, user, nickname: nil, user_verified: true)
    options = controller.passkey_registration_options(user)
    raw = fake_client.create(challenge: options.challenge, user_verified: user_verified)
    controller.passkey_register!(user, raw, nickname: nickname)
  end
end
