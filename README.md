# SecurityKey

<img src="docs/logo.svg" width="140"
  alt="The passkeyed mark: a red fingerprint inside a light shield, on a
       dark rounded tile.">

Passwordless, usernameless passkey ([WebAuthn](https://www.w3.org/TR/webauthn-2/))
authentication for Rails, built on
[webauthn-ruby](https://github.com/cedarcode/webauthn-ruby). No mountable
engine hiding the flow: you get a model concern, a controller concern exposing
four methods, and a Stimulus controller — you write your own routes,
controllers, and views.

A passkey is a public/private key pair created for one site. The private key
never leaves the user's device, your server stores only the public half, and
the browser binds each credential to its origin — nothing to phish, nothing
worth stealing from your database.

Companion to a two-part series:
[*Passkeys from first principles*](https://www.pardel.dev/2026/06/28/passkeys-from-first-principles.html)
(what passkeys are and how the ceremonies work) and
[*Building passkeys in Ruby on Rails*](https://www.pardel.dev/2026/07/04/passkeys-in-ruby-on-rails.html)
(the from-scratch build this gem packages).

## Installation

```ruby
gem "passkeyed"
```

```sh
bundle install
bin/rails generate passkeyed:install
bin/rails db:migrate
```

The generator adds the `passkeyed_credentials` table, a `webauthn_id` column
on your owner model (backfilled for existing rows, so current users can
register passkeys immediately), an initializer, the Stimulus controller, and
`include Passkeyed::Model` in your model.

There is no JavaScript dependency: the Stimulus controller uses the browser's
native `PublicKeyCredential` JSON methods
([shipped in every major browser](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential))
and reports passkeys as unavailable on a browser too old to have them.

## Configuration

`config/initializers/passkeyed.rb`:

```ruby
Passkeyed.configure do |config|
  config.rp_name           = "Acme"
  config.rp_id             = "acme.example"            # optional in dev
  config.allowed_origins   = ["https://acme.example"]  # required when deployed
  config.user_verification = "required"
  config.challenge_timeout = 300                       # seconds a challenge stays valid
end
```

In any environment other than `development` and `test`, boot fails with a
`Passkeyed::ConfigurationError` when `allowed_origins` is blank or non-HTTPS
(WebAuthn requires a secure context), so the generated localhost default can't
silently ship. passkeyed never writes to webauthn-ruby's global configuration —
it hands an isolated `WebAuthn::RelyingParty` to every call — so an app using
webauthn-ruby directly keeps its own settings.

## Usage

Mix the ceremony helpers into a controller. Each ceremony is a challenge that
the authenticator signs and the server verifies.

```ruby
class RegistrationsController < ApplicationController
  include Passkeyed::Ceremonies

  # POST /passkeys/registration_options
  def options
    render json: passkey_registration_options(current_user)
  end

  # POST /passkeys
  def create
    passkey_register!(current_user, params[:credential], nickname: params[:nickname])
    render json: { status: "ok" }
  rescue Passkeyed::Error => e
    render json: { error: e.message }, status: :unprocessable_entity
  end
end

class SessionsController < ApplicationController
  include Passkeyed::Ceremonies

  # POST /session/options
  def options
    render json: passkey_authentication_options
  end

  # POST /session
  def create
    user = passkey_authenticate!(params[:credential])
    session[:user_id] = user.id
    render json: { status: "ok" }
  rescue Passkeyed::Error
    render json: { error: "Authentication failed" }, status: :unauthorized
  end
end
```

Wire the Stimulus controller in your views. To register a passkey (the optional
`nickname` input lets the user label the device):

```erb
<div data-controller="passkey"
     data-passkey-registration-options-url-value="<%= options_passkeys_path %>"
     data-passkey-registration-url-value="<%= passkeys_path %>"
     data-passkey-redirect-url-value="<%= dashboard_path %>">
  <input data-passkey-target="nickname" placeholder="Laptop">
  <button data-action="passkey#register">Add a passkey</button>
  <p data-passkey-target="error" role="alert"></p>
</div>
```

To sign in:

```erb
<div data-controller="passkey"
     data-passkey-authentication-options-url-value="<%= options_session_path %>"
     data-passkey-authentication-url-value="<%= session_path %>"
     data-passkey-redirect-url-value="<%= dashboard_path %>">
  <button data-action="passkey#authenticate">Sign in with a passkey</button>
  <p data-passkey-target="error" role="alert"></p>
</div>
```

(`role="alert"` makes screen readers announce a ceremony failure.)

### Conditional UI (passkey autofill)

Add `data-passkey-conditional-value="true"` and an input marked
`autocomplete="username webauthn"` to also offer passkeys through the
browser's autofill:

```erb
<div data-controller="passkey"
     data-passkey-conditional-value="true"
     data-passkey-authentication-options-url-value="<%= options_session_path %>"
     data-passkey-authentication-url-value="<%= session_path %>"
     data-passkey-redirect-url-value="<%= dashboard_path %>">
  <input type="text" autocomplete="username webauthn" placeholder="you@example.com">
  <button data-action="passkey#authenticate">Sign in with a passkey</button>
  <p data-passkey-target="error" role="alert"></p>
</div>
```

The feature is skipped where the browser lacks it, a modal ceremony or
navigation aborts the pending request cleanly, and a failed attempt (a
dismissed sheet, an expired challenge) re-arms autofill automatically.

### Reacting to a ceremony from JavaScript

After a successful ceremony the controller dispatches a cancelable
`passkey:registered` / `passkey:authenticated` event (detail: the server's
JSON response) before following `data-passkey-redirect-url-value` (or
reloading). Call `event.preventDefault()` to take over — e.g. to update the
page with Turbo. Failures dispatch `passkey:error`.

## Public API

| Method | Purpose |
|---|---|
| `Passkeyed::Model` | Include in the owner model: credentials association + `webauthn_id`. |
| `passkey_registration_options(user)` | Build creation options (discoverable), stash the challenge. |
| `passkey_register!(user, credential, nickname:)` | Verify and persist a new credential. |
| `passkey_authentication_options` | Build request options (no allow-list), stash the challenge. |
| `passkey_authenticate!(credential)` | Verify an assertion and return the owner. |

All ceremony failures raise `Passkeyed::Error` or a subclass
(`RegistrationError`, `AuthenticationError`, `CredentialNotFound`,
`ChallengeMissing`, `ChallengeExpired`).

### Managing a user's passkeys

List, rename, and revoke through the owner, so a mismatched id raises
`ActiveRecord::RecordNotFound` instead of touching another account's
credential:

```ruby
current_user.passkeyed_credentials            # list (id, nickname, created_at, ...)
current_user.rename_passkey(id, "Work Laptop")
current_user.revoke_passkey(id)               # guard the last passkey in your app
```

Each credential also records metadata for richer management UIs:

| Column | Meaning |
|---|---|
| `backed_up` / `backup_eligible` | Synced passkey (iCloud Keychain, Google Password Manager) vs device-bound. Refreshed on every sign-in. |
| `transports` | How the authenticator talks to clients, e.g. `["internal", "hybrid"]`. |
| `aaguid` | The authenticator model's UUID (nil when zeroed); map to names via the [community AAGUID list](https://github.com/passkeydeveloper/passkey-authenticator-aaguids). |
| `last_used_at` | Stamped on every successful assertion. |

The user entity sent at registration uses `passkey_name` (an email by default)
and `passkey_display_name` (defaults to `passkey_name`). Override either in
your model.

### Hooks

Override these private no-op methods in your controller to run after a
successful ceremony:

```ruby
def after_passkey_authentication(credential, user)
  AuditLog.record(:passkey_sign_in, user:, credential:)
end
```

`after_passkey_registration(credential)` is the registration counterpart. Both
run with full controller context and outside the ceremony's error handling, so
an exception you raise surfaces as itself.

### Instrumentation

Both bang methods emit `ActiveSupport::Notifications` events —
`register.passkeyed` and `authenticate.passkeyed` — with `:credential`/`:user`
in the payload and, unlike the success-only hooks, the standard `:exception`
keys on failure, so probing is observable:

```ruby
ActiveSupport::Notifications.subscribe("authenticate.passkeyed") do |event|
  next unless event.payload[:exception]

  Rails.logger.warn("passkey sign-in failed: #{event.payload[:exception_object]&.message}")
end
```

## Notes and non-goals

- **Signature counter.** A non-increasing `sign_count` from an authenticator
  that reports nonzero counts raises `Passkeyed::AuthenticationError` — the
  classic cloned-authenticator signal. Synced passkeys report zero on both
  sides and are exempt.
- **Return one generic message for failed sign-ins**, as the example above
  does: rescue `Passkeyed::AuthenticationError` (which `CredentialNotFound`
  subclasses) so you don't reveal whether a credential id is on record.
  Response *timing* can still hint at it — an unknown id skips the signature
  check — so pair the generic message with rate limiting.
- **Rate-limit the ceremony endpoints.** They are unauthenticated and run
  public-key crypto on every request. On Rails 8+:
  `rate_limit to: 10, within: 1.minute, only: %i[options create]`; on older
  Rails, use `rack-attack`.
- **Sessions and CSRF.** Challenges are stashed in `session`, and the Stimulus
  controller sends the CSRF token from the `csrf_meta_tags` meta tag — both
  standard in a full-stack Rails app. In an API-only app, add session
  middleware (or override `passkeyed_session`) and your own
  request-authenticity scheme.
- **Account recovery** is your responsibility: plan for the user who loses
  their device (a second passkey, or an out-of-band recovery path).
- Out of scope: password fallback, passkeys-as-second-factor, attestation
  verification, and Devise integration.

## Development

```sh
bin/setup
bundle exec rake test              # Minitest; ceremonies driven by WebAuthn::FakeClient
node --test test/javascript/*.test.mjs   # Stimulus controller tests, no npm install
```

CI also runs the suite against the oldest supported Rails:
`BUNDLE_GEMFILE=gemfiles/rails_7.1.gemfile bundle exec rake test`.

## License

[MIT](LICENSE.txt).
