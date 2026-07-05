# frozen_string_literal: true

module Passkeyed
  # A stored passkey: the public half of a WebAuthn credential, plus the
  # signature counter used to spot cloned authenticators. The private key
  # never reaches us, so there is nothing secret in this table.
  #
  # The owner is polymorphic (+user+) so any model can hold passkeys, not just
  # one called User.
  class Credential < Passkeyed.base_record_class
    self.table_name = "passkeyed_credentials"

    belongs_to :user, polymorphic: true, optional: false

    # The WebAuthn credential id (base64url). Unique across the whole table:
    # authentication looks a credential up by this alone.
    validates :external_id, presence: true, uniqueness: true
    validates :public_key, presence: true
    validates :sign_count,
              presence: true,
              numericality: { only_integer: true, greater_than_or_equal_to: 0 }
    # Optional user-supplied label. Cap it at the string column's width so a long
    # value is rejected cleanly rather than silently truncated (e.g. on MySQL).
    validates :nickname, length: { maximum: 255 }, allow_nil: true

    # Persist the state a successful assertion produces: the advanced signature
    # counter, and — when the columns are present — a last-used timestamp and
    # the current backup state (a device-bound passkey may later start syncing,
    # flipping the flag). The columns are guarded so authentication keeps
    # working on apps that trimmed the optional columns from the migration.
    def record_sign_in!(new_sign_count, backed_up: nil)
      attributes = { sign_count: new_sign_count }
      attributes[:last_used_at] = Time.current if has_attribute?(:last_used_at)
      attributes[:backed_up] = backed_up if !backed_up.nil? && has_attribute?(:backed_up)
      assign_attributes(attributes)
      # Everything written here is server-derived, so skip validations: a record
      # invalid by rules added after it was persisted (e.g. a nickname cap
      # introduced in a future version) must not start failing every sign-in.
      save!(validate: false)
    end

    # +transports+ is stored as a JSON string (portable across databases);
    # expose it as the Array WebAuthn reported, e.g. ["internal", "hybrid"].
    # Unparseable stored data (a manual write, a botched import) reads as nil
    # rather than raising out of every page that lists credentials.
    def transports
      raw = super
      raw.is_a?(String) ? JSON.parse(raw) : raw
    rescue JSON::ParserError
      nil
    end

    def transports=(value)
      value = JSON.generate(value) unless value.nil? || value.is_a?(String)
      super
    end
  end
end
