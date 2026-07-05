// Tests for the generated Stimulus controller. Run with:
//   node --test test/javascript/passkey_controller.test.mjs
//
// No npm install: the controller template is loaded verbatim, but its bare
// import (@hotwired/stimulus) is rewritten to a local mock module before
// import, and the browser globals the controller touches (window, navigator,
// document, fetch) are hand-rolled per test. WebAuthn itself is exercised
// through stubs for the native PublicKeyCredential JSON methods and
// navigator.credentials.

import { test, beforeEach } from "node:test"
import assert from "node:assert/strict"
import { readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, dirname } from "node:path"
import { pathToFileURL } from "node:url"

const here = import.meta.dirname
const template = join(
  dirname(here),
  "..",
  "lib/generators/passkeyed/install/templates/passkey_controller.js"
)

// Point the template's bare import at the local mock, then load it as ESM.
const source = readFileSync(template, "utf8")
  .replace('"@hotwired/stimulus"', JSON.stringify(pathToFileURL(join(here, "mocks/stimulus.mjs")).href))
const copy = join(tmpdir(), "passkeyed_passkey_controller.test.mjs")
writeFileSync(copy, source)
const { default: PasskeyController } = await import(pathToFileURL(copy))

// A DOM-free environment exposing only what the controller reads.
let fetchCalls
let redirectTo
let errorTarget

function buildController({
  csrf = null,
  webauthnAvailable = true,
  jsonMethods = true,
  conditionalMediation = null
} = {}) {
  fetchCalls = []
  redirectTo = null
  errorTarget = { textContent: "" }

  // The native serialisation surface: parse* pass the JSON through (the
  // controller treats the parsed value as opaque), toJSON comes from the
  // credential stubs below.
  const publicKeyCredential = webauthnAvailable ? function () {} : undefined
  if (publicKeyCredential && jsonMethods) {
    publicKeyCredential.parseCreationOptionsFromJSON = (json) => json
    publicKeyCredential.parseRequestOptionsFromJSON = (json) => json
  }
  if (publicKeyCredential && conditionalMediation !== null) {
    publicKeyCredential.isConditionalMediationAvailable = async () => conditionalMediation
  }

  global.window = {
    PublicKeyCredential: publicKeyCredential,
    isSecureContext: webauthnAvailable,
    location: {
      assign: (url) => { redirectTo = url },
      reload: () => { redirectTo = "reload" }
    }
  }
  // Node ships its own read-only `navigator` global, so plain assignment throws.
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      credentials: {
        create: (...args) => globalThis.__passkeyCreate(...args),
        get: (...args) => globalThis.__passkeyGet(...args)
      }
    }
  })
  global.document = {
    querySelector: () => (csrf ? { content: csrf } : null)
  }
  global.fetch = async (url, options) => {
    fetchCalls.push({ url, options })
    return { ok: true, status: 200, json: async () => ({ status: "ok" }) }
  }

  const controller = new PasskeyController()
  controller.registrationOptionsUrlValue = "/registration_options"
  controller.registrationUrlValue = "/registration"
  controller.authenticationOptionsUrlValue = "/authentication_options"
  controller.authenticationUrlValue = "/authentication"
  controller.hasRedirectUrlValue = true
  controller.redirectUrlValue = "/dashboard"
  controller.hasNicknameTarget = false
  controller.hasErrorTarget = true
  controller.errorTarget = errorTarget
  controller.conditionalValue = false
  return controller
}

// A credential as navigator.credentials returns it: toJSON() is what the
// controller must POST.
const fakeCredential = () => ({ toJSON: () => ({ id: "cred" }) })

const event = () => ({ preventDefault() {}, currentTarget: { disabled: false } })

// Spin the event loop until `condition` holds (or give up), for waiting on a
// ceremony to reach its hanging create()/get() before the test releases it.
async function tickUntil(condition, tries = 50) {
  for (let i = 0; i < tries && !condition(); i++) {
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
}

beforeEach(() => {
  globalThis.__passkeyCreate = async () => fakeCredential()
  globalThis.__passkeyGet = async () => fakeCredential()
  globalThis.__passkeyDispatchListener = null
})

test("registration succeeds and redirects", async () => {
  const controller = buildController()

  await controller.register(event())

  assert.equal(redirectTo, "/dashboard")
  assert.equal(errorTarget.textContent, "")
  assert.deepEqual(fetchCalls.map((c) => c.url), [
    "/registration_options",
    "/registration"
  ])
})

test("posts the credential's toJSON() serialisation", async () => {
  const controller = buildController()

  await controller.register(event())

  const body = JSON.parse(fetchCalls[1].options.body)
  assert.deepEqual(body.credential, { id: "cred" })
})

test("hands the parsed options to navigator.credentials", async () => {
  const controller = buildController()
  let received
  globalThis.__passkeyCreate = async (args) => {
    received = args
    return fakeCredential()
  }

  await controller.register(event())

  // parse* is the identity in the stub, so publicKey is the server's JSON.
  assert.deepEqual(received.publicKey, { status: "ok" })
})

test("omits the CSRF header when no token is present", async () => {
  const controller = buildController({ csrf: null })

  await controller.register(event())

  const headers = fetchCalls[0].options.headers
  assert.equal("X-CSRF-Token" in headers, false)
})

test("sends the CSRF header when a token is present", async () => {
  const controller = buildController({ csrf: "tok-123" })

  await controller.register(event())

  assert.equal(fetchCalls[0].options.headers["X-CSRF-Token"], "tok-123")
})

test("does not surface a cancelled prompt (NotAllowedError)", async () => {
  const controller = buildController()
  globalThis.__passkeyCreate = async () => {
    throw Object.assign(new Error("nope"), { name: "NotAllowedError" })
  }

  await controller.register(event())

  assert.equal(errorTarget.textContent, "")
  assert.equal(redirectTo, null)
})

test("surfaces a real error to the error target and dispatches it", async () => {
  const controller = buildController()
  globalThis.__passkeyCreate = async () => { throw new Error("boom") }

  await controller.register(event())

  assert.equal(errorTarget.textContent, "boom")
  assert.equal(redirectTo, null)
  const errorEvent = controller.dispatched.find((e) => e.name === "error")
  assert.equal(errorEvent.detail.error.message, "boom")
})

test("reports when WebAuthn is unavailable and makes no request", async () => {
  const controller = buildController({ webauthnAvailable: false })

  await controller.register(event())

  assert.match(errorTarget.textContent, /aren't available/)
  assert.equal(fetchCalls.length, 0)
})

test("reports unavailability when the native JSON methods are missing", async () => {
  // Old browser: WebAuthn exists but parse*FromJSON/toJSON don't.
  const controller = buildController({ jsonMethods: false })

  await controller.register(event())

  assert.match(errorTarget.textContent, /aren't available/)
  assert.equal(fetchCalls.length, 0)
})

test("the busy guard blocks a concurrent ceremony", async () => {
  const controller = buildController()
  let release
  globalThis.__passkeyCreate = () => new Promise((resolve) => { release = resolve })

  const first = controller.register(event())
  await tickUntil(() => typeof release === "function") // first ceremony now hangs in create()
  await controller.register(event()) // should bail: #busy is set

  // Only the first ceremony's options request went out.
  assert.equal(fetchCalls.filter((c) => c.url === "/registration_options").length, 1)

  release(fakeCredential())
  await first
})

test("dispatches a cancelable registered event before redirecting", async () => {
  const controller = buildController()

  await controller.register(event())

  const finished = controller.dispatched.find((e) => e.name === "registered")
  assert.deepEqual(finished.detail, { status: "ok" })
  assert.equal(finished.cancelable, true)
  assert.equal(redirectTo, "/dashboard")
})

test("preventDefault on the outcome event suppresses the redirect", async () => {
  const controller = buildController()
  globalThis.__passkeyDispatchListener = (e) => {
    if (e.name === "authenticated") e.preventDefault()
  }

  await controller.authenticate(event())

  assert.equal(redirectTo, null)
  assert.equal(fetchCalls.map((c) => c.url).at(-1), "/authentication")
})

// --- conditional UI (passkey autofill) --------------------------------------

test("connect() starts a conditional assertion when enabled and available", async () => {
  const controller = buildController({ conditionalMediation: true })
  controller.conditionalValue = true
  let received
  globalThis.__passkeyGet = async (args) => {
    received = args
    return fakeCredential()
  }

  controller.connect()
  await tickUntil(() => redirectTo !== null)

  assert.equal(received.mediation, "conditional")
  assert.ok(received.signal instanceof AbortSignal)
  assert.equal(redirectTo, "/dashboard")
  assert.deepEqual(fetchCalls.map((c) => c.url), [
    "/authentication_options",
    "/authentication"
  ])
})

test("conditional UI is skipped when the browser doesn't offer it", async () => {
  const controller = buildController({ conditionalMediation: false })
  controller.conditionalValue = true

  controller.connect()
  await tickUntil(() => fetchCalls.length > 0, 10)

  assert.equal(fetchCalls.length, 0)
})

test("disconnect() aborts the pending conditional request quietly", async () => {
  const controller = buildController({ conditionalMediation: true })
  controller.conditionalValue = true
  let sawSignal
  globalThis.__passkeyGet = ({ signal }) => new Promise((_resolve, reject) => {
    sawSignal = signal
    signal.addEventListener("abort", () => {
      reject(Object.assign(new Error("aborted"), { name: "AbortError" }))
    })
  })

  controller.connect()
  await tickUntil(() => sawSignal !== undefined)
  controller.disconnect()
  await tickUntil(() => sawSignal.aborted)

  assert.equal(sawSignal.aborted, true)
  assert.equal(errorTarget.textContent, "") // AbortError is a normal outcome
  assert.equal(redirectTo, null)
})

test("a failed conditional assertion re-arms autofill", async () => {
  const controller = buildController({ conditionalMediation: true })
  controller.conditionalValue = true
  let getCalls = 0
  globalThis.__passkeyGet = async () => {
    getCalls++
    if (getCalls === 1) return fakeCredential()
    return new Promise(() => {}) // the second round parks behind autofill again
  }
  // The server rejects the first assertion (e.g. an expired challenge after an
  // idle tab); without a restart, autofill would be dead until a full reload.
  let authenticationPosts = 0
  global.fetch = async (url, options) => {
    fetchCalls.push({ url, options })
    if (url === "/authentication" && ++authenticationPosts === 1) {
      return { ok: false, status: 401, json: async () => ({ error: "expired" }) }
    }
    return { ok: true, status: 200, json: async () => ({ status: "ok" }) }
  }

  controller.connect()
  await tickUntil(() => getCalls === 2)

  assert.equal(getCalls, 2) // a fresh conditional request is pending
  assert.equal(errorTarget.textContent, "expired")
  assert.equal(redirectTo, null)
})

test("an aborted conditional request does not re-arm itself", async () => {
  const controller = buildController({ conditionalMediation: true })
  controller.conditionalValue = true
  let getCalls = 0
  globalThis.__passkeyGet = ({ signal }) => new Promise((_resolve, reject) => {
    getCalls++
    signal.addEventListener("abort", () => {
      reject(Object.assign(new Error("aborted"), { name: "AbortError" }))
    })
  })

  controller.connect()
  await tickUntil(() => getCalls === 1)
  controller.disconnect()
  // Give a wrongly-scheduled restart a chance to fire before asserting.
  await tickUntil(() => getCalls > 1, 10)

  assert.equal(getCalls, 1)
})

test("a modal ceremony aborts the pending conditional request first", async () => {
  const controller = buildController({ conditionalMediation: true })
  controller.conditionalValue = true
  let conditionalSignal
  globalThis.__passkeyGet = (args) => {
    if (args.mediation === "conditional") {
      return new Promise((_resolve, reject) => {
        conditionalSignal = args.signal
        args.signal.addEventListener("abort", () => {
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }))
        })
      })
    }
    return Promise.resolve(fakeCredential())
  }

  controller.connect()
  await tickUntil(() => conditionalSignal !== undefined)
  await controller.authenticate(event())

  assert.equal(conditionalSignal.aborted, true)
  assert.equal(redirectTo, "/dashboard")
})
