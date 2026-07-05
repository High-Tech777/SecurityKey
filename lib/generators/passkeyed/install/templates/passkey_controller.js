import { Controller } from "@hotwired/stimulus"

// Drives the two WebAuthn ceremonies from the browser. The endpoints are
// supplied as Stimulus values, so this controller stays app-agnostic:
//
//   <div data-controller="passkey"
//        data-passkey-registration-options-url-value="/passkeys/registration_options"
//        data-passkey-registration-url-value="/passkeys"
//        data-passkey-redirect-url-value="/dashboard">
//     <input data-passkey-target="nickname">
//     <button data-action="passkey#register">Add a passkey</button>
//     <p data-passkey-target="error" role="alert"></p>
//   </div>
//
// Serialisation uses the browser's own PublicKeyCredential JSON methods
// (parseCreationOptionsFromJSON / parseRequestOptionsFromJSON / toJSON), which
// handle the base64url <-> ArrayBuffer conversion natively — no JavaScript
// dependency needed.
//
// Set data-passkey-conditional-value="true" on a sign-in form to also offer
// passkeys through the browser's autofill (conditional UI). Pair it with an
// <input autocomplete="username webauthn"> inside the same element.
//
// After a successful ceremony the controller dispatches a cancelable
// "passkey:registered" / "passkey:authenticated" event (detail: the server's
// JSON response) and then follows data-passkey-redirect-url-value (or reloads).
// Call event.preventDefault() in a listener to handle the outcome yourself.
export default class extends Controller {
  static values = {
    registrationOptionsUrl: String,
    registrationUrl: String,
    authenticationOptionsUrl: String,
    authenticationUrl: String,
    redirectUrl: String,
    conditional: Boolean
  }

  static targets = ["error", "nickname"]

  // Re-entrancy guard: a second ceremony would rotate the server's challenge
  // and make the first fail confusingly.
  #busy = false

  // Aborts the pending conditional (autofill) request: browsers allow only one
  // in-flight WebAuthn request, so a modal ceremony must cancel it first.
  #conditionalAbort = null

  connect() {
    if (this.conditionalValue) this.#startConditional()
  }

  disconnect() {
    this.#abortConditional()
  }

  async register(event) {
    event.preventDefault()
    await this.#runCeremony(event, async () => {
      const optionsJSON = await this.#postJson(this.registrationOptionsUrlValue)
      const options = window.PublicKeyCredential.parseCreationOptionsFromJSON(optionsJSON)
      // Prompts for Touch ID / Windows Hello / a PIN and mints the key pair
      // inside the device's secure hardware.
      const credential = await navigator.credentials.create({ publicKey: options })

      const body = { credential: credential.toJSON() }
      if (this.hasNicknameTarget && this.nicknameTarget.value) {
        body.nickname = this.nicknameTarget.value
      }

      const response = await this.#postJson(this.registrationUrlValue, body)
      this.#finish("registered", response)
    })
  }

  async authenticate(event) {
    event.preventDefault()
    await this.#runCeremony(event, async () => {
      const response = await this.#assert()
      this.#finish("authenticated", response)
    })
  }

  // The assertion ceremony shared by the modal button and the autofill path:
  // fetch options, let the authenticator sign, post the assertion back.
  async #assert(mediationOptions = {}) {
    const optionsJSON = await this.#postJson(this.authenticationOptionsUrlValue)
    const options = window.PublicKeyCredential.parseRequestOptionsFromJSON(optionsJSON)
    // The browser shows the account picker and asks for the user's gesture.
    const credential = await navigator.credentials.get({
      publicKey: options,
      ...mediationOptions
    })

    return this.#postJson(this.authenticationUrlValue, { credential: credential.toJSON() })
  }

  // Conditional UI: park an assertion request behind the browser's autofill,
  // so a <input autocomplete="username webauthn"> offers stored passkeys. The
  // request hangs until the user picks one (or it is aborted), so it must not
  // take the busy lock that guards the modal ceremonies.
  async #startConditional() {
    if (!this.#webAuthnAvailable()) return
    if (!window.PublicKeyCredential.isConditionalMediationAvailable) return
    if (!(await window.PublicKeyCredential.isConditionalMediationAvailable())) return
    if (this.#conditionalAbort) return

    this.#conditionalAbort = new AbortController()
    let restart = false
    try {
      const response = await this.#assert({
        mediation: "conditional",
        signal: this.#conditionalAbort.signal
      })
      this.#finish("authenticated", response)
    } catch (error) {
      this.#handleError(error)
      // Re-arm autofill unless the abort was deliberate (a modal ceremony took
      // over, or the element disconnected). The user dismissing the sheet, or
      // the server rejecting the assertion (say, an expired challenge in an
      // idle tab), would otherwise leave passkey autofill dead until a reload.
      restart = error.name !== "AbortError"
    } finally {
      this.#conditionalAbort = null
    }
    if (restart) this.#startConditional()
  }

  #abortConditional() {
    if (this.#conditionalAbort) {
      this.#conditionalAbort.abort()
      this.#conditionalAbort = null
    }
  }

  // Shared ceremony scaffolding: feature-detect, guard against double-submit,
  // disable the button for the duration, then run the body. On failure the
  // conditional request is restarted so autofill keeps working after a
  // cancelled modal prompt.
  async #runCeremony(event, body) {
    if (this.#busy) return
    this.#clearError()

    if (!this.#webAuthnAvailable()) {
      this.#showMessage("Passkeys aren't available in this browser.")
      return
    }

    this.#abortConditional()

    const button = event.currentTarget
    this.#busy = true
    if (button) button.disabled = true

    try {
      await body()
    } catch (error) {
      this.#handleError(error)
      if (this.conditionalValue) this.#startConditional()
    } finally {
      this.#busy = false
      if (button) button.disabled = false
    }
  }

  async #postJson(url, body) {
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json"
    }
    // Only send the header when the token exists; otherwise fetch coerces
    // `undefined` to the literal string "undefined" and the POST 422s.
    const csrfToken = this.#csrfToken()
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken

    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers,
      body: body ? JSON.stringify(body) : "{}"
    })

    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      throw new Error(data.error || `Request failed (${response.status})`)
    }

    return response.json()
  }

  // Requires the native JSON serialisation methods alongside WebAuthn itself;
  // both have shipped in every major browser (see MDN: PublicKeyCredential).
  #webAuthnAvailable() {
    return Boolean(
      window.PublicKeyCredential &&
        window.isSecureContext &&
        window.PublicKeyCredential.parseCreationOptionsFromJSON &&
        window.PublicKeyCredential.parseRequestOptionsFromJSON
    )
  }

  #csrfToken() {
    return document.querySelector("meta[name='csrf-token']")?.content
  }

  #handleError(error) {
    // Cancelling the OS prompt or letting it time out rejects with
    // NotAllowedError (and AbortError for an aborted request) — a normal
    // outcome, not something to show as a failure.
    if (error.name === "NotAllowedError" || error.name === "AbortError") return

    this.#showError(error)
  }

  // Announce the outcome, then redirect unless a listener claimed it.
  #finish(eventName, detail) {
    const event = this.dispatch(eventName, { detail, cancelable: true })
    if (event.defaultPrevented) return

    this.#redirect()
  }

  #redirect() {
    if (this.hasRedirectUrlValue) {
      window.location.assign(this.redirectUrlValue)
    } else {
      window.location.reload()
    }
  }

  #showError(error) {
    this.dispatch("error", { detail: { error } })
    this.#showMessage(error.message)
  }

  #showMessage(message) {
    if (this.hasErrorTarget) {
      this.errorTarget.textContent = message
    } else {
      console.error(message)
    }
  }

  #clearError() {
    if (this.hasErrorTarget) this.errorTarget.textContent = ""
  }
}
