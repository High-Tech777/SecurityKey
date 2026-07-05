# frozen_string_literal: true

require "active_support/concern"

module Passkeyed
  # Mix into the model that owns passkeys (typically your User):
  #
  #   class User < ApplicationRecord
  #     include Passkeyed::Model
  #   end
  #
  # It wires up the credentials association and assigns the random WebAuthn
  # user handle (+webauthn_id+) on create. The host table needs a
  # +webauthn_id:string+ column (the install generator adds it).
  module Model
    extend ActiveSupport::Concern

    included do
      has_many :passkeyed_credentials,
               class_name: "Passkeyed::Credential",
               as: :user,
               dependent: :destroy

      before_create :assign_passkeyed_webauthn_id
    end

    # The name passed to the authenticator at registration time. Prefers an
    # +email+, then a +name+, falling back to the opaque handle. Override in
    # your model if you want something else shown.
    def passkey_name
      return email if respond_to?(:email) && email.present?
      return name if respond_to?(:name) && name.present?

      passkeyed_webauthn_id!
    end

    # The human-friendly display name (WebAuthn's user.displayName) shown by
    # account pickers, distinct from +passkey_name+ (the account identifier).
    # Defaults to +passkey_name+; override to show e.g. a full name next to an
    # email.
    def passkey_display_name
      passkey_name
    end

    # Rename one of this owner's passkeys (e.g. from a credential-management UI).
    # Looked up *through the association*, so an id belonging to another owner
    # raises ActiveRecord::RecordNotFound rather than letting one user relabel
    # another's credential. A blank nickname clears the label. Returns the
    # credential.
    def rename_passkey(credential_id, nickname)
      credential = passkeyed_credentials.find(credential_id)
      credential.update!(nickname: nickname.presence)
      credential
    end

    # Revoke (delete) one of this owner's passkeys. Scoped through the
    # association like +rename_passkey+. Returns the destroyed credential; raises
    # ActiveRecord::RecordNotFound if the id isn't this owner's.
    #
    # This does not stop a user removing their last passkey — guard against that
    # in your app if it would lock the account out.
    def revoke_passkey(credential_id)
      passkeyed_credentials.find(credential_id).destroy!
    end

    # Return this record's WebAuthn user handle, assigning one when absent.
    # +before_create+ only covers rows created after the gem is installed, so a
    # pre-existing user (or one whose backfill was missed) would otherwise reach
    # the ceremony with a nil handle, which webauthn-ruby drops from the options
    # JSON and the browser then rejects. Persists the handle when the record is
    # already saved; assigns it in memory otherwise (the +before_create+ keeps
    # it for an unsaved record). Raises if the +webauthn_id+ column is missing.
    def passkeyed_webauthn_id!
      ensure_webauthn_id_column!
      return webauthn_id if webauthn_id.present?

      handle = WebAuthn.generate_user_id
      self.webauthn_id = handle
      update_column(:webauthn_id, handle) if persisted?
      handle
    end

    private

    def assign_passkeyed_webauthn_id
      ensure_webauthn_id_column!
      self.webauthn_id ||= WebAuthn.generate_user_id
    end

    def ensure_webauthn_id_column!
      return if self.class.column_names.include?("webauthn_id")

      raise Passkeyed::ConfigurationError,
            "#{self.class.name} has no webauthn_id column; run the passkeyed install migration " \
            "(bin/rails generate passkeyed:install && bin/rails db:migrate)"
    end
  end
end
