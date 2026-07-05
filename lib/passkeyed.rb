# frozen_string_literal: true

require "webauthn"
require "active_support"

require "passkeyed/version"
require "passkeyed/errors"
require "passkeyed/configuration"

# passkeyed adds passwordless, usernameless passkey (WebAuthn) authentication
# to Rails apps as a small, transparent runtime plus an install generator.
#
# The heavier pieces (the ActiveRecord credential model and the two concerns)
# are autoloaded so the gem can be required before ActiveRecord is ready.
module Passkeyed
  autoload :Credential, "passkeyed/credential"
  autoload :Model, "passkeyed/model"
  autoload :Ceremonies, "passkeyed/ceremonies"
end
