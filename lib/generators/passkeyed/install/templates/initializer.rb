# frozen_string_literal: true

# Passkeyed configuration. See https://github.com/pardel/passkeyed.
Passkeyed.configure do |config|
  # Shown by some authenticators during a ceremony.
  config.rp_name = Rails.application.class.module_parent_name

  # Your domain. Leave commented to derive it from the request origin in
  # development; set it explicitly in production (e.g. "example.com").
  # config.rp_id = "example.com"

  # Origins the server will accept assertions from. Required (and must be
  # https) in any environment other than development and test.
  config.allowed_origins = ["http://localhost:3000"]

  # "required" makes a single passkey gesture genuinely multi-factor.
  config.user_verification = "required"

  # How long (in seconds) an issued challenge may sit unsigned before the
  # ceremony must be restarted. The default suits almost everyone.
  # config.challenge_timeout = 300
end

# The ActiveRecord base class Passkeyed::Credential inherits from. Defaults to
# ApplicationRecord when defined. Set this ONLY if you need a different base
# (e.g. a secondary database), and set it *here*, before anything references
# Passkeyed::Credential: the parent class is resolved once, when that constant
# is first loaded, so a later assignment is ignored.
#
# Passkeyed.base_record_class = "SecondaryRecord"
