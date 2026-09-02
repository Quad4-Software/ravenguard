import { RavenGuardWidget } from './widget'

export {
  encodePayload,
  decodePayload,
  solveChallenge,
  verifySHA256,
  verifyPBKDF2,
  leadingZeroBits,
  PROTOCOL_VERSION,
  type Challenge,
  type Payload,
  type EnvAttestation,
  type WidgetState,
  type Algorithm,
} from './protocol'

export {
  RavenGuardWidget,
  RavenGuardWidget as RGCheck,
  type WidgetOptions,
  type AutoMode,
} from './widget'

let primaryDefined = false

export function register(tag = 'rg-check') {
  if (typeof customElements === 'undefined') return
  if (customElements.get(tag)) return
  if (!primaryDefined) {
    customElements.define(tag, RavenGuardWidget)
    primaryDefined = true
    return
  }
  customElements.define(tag, class extends RavenGuardWidget {})
}

register()
register('ravenguard-widget')

export default RavenGuardWidget
