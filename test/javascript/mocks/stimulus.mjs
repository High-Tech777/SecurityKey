// Minimal stand-in for @hotwired/stimulus. Real Stimulus generates the value
// and target accessors from `static values`/`static targets`; the tests set
// those directly on the instance instead. dispatch() mirrors Stimulus's
// controller.dispatch: it records the event and returns it, honouring
// preventDefault() so tests can claim an outcome the way a listener would.
export class Controller {
  dispatched = []

  dispatch(name, { detail, cancelable = false } = {}) {
    const event = {
      name,
      detail,
      cancelable,
      defaultPrevented: false,
      preventDefault() {
        if (this.cancelable) this.defaultPrevented = true
      }
    }
    this.dispatched.push(event)
    globalThis.__passkeyDispatchListener?.(event)
    return event
  }
}
