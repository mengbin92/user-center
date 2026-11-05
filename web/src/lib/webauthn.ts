import type {
  CompleteMFARequest,
  ConfirmWebAuthnRegistrationRequest,
  VerifyWebAuthnAssertionRequest,
  WebAuthnAssertionChallengeReply,
  WebAuthnRegistrationChallengeReply,
} from './types'

function toBuffer(raw: string): ArrayBuffer {
  const padded = raw.replace(/-/g, '+').replace(/_/g, '/')
  const value = padded + '='.repeat((4 - (padded.length % 4)) % 4)
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function browserSupported(): boolean {
  return typeof navigator !== 'undefined' && !!navigator.credentials && typeof PublicKeyCredential !== 'undefined'
}

export async function createPasskey(
  challenge: WebAuthnRegistrationChallengeReply,
  challengeId: string,
  name: string,
): Promise<ConfirmWebAuthnRegistrationRequest> {
  if (!browserSupported()) throw new Error('当前浏览器不支持 Passkey，请使用 HTTPS 或更换浏览器')
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: toBuffer(challenge.challenge ?? ''),
    rp: { id: challenge.rp_id ?? '', name: challenge.rp_name ?? '用户中心' },
    user: {
      id: new TextEncoder().encode(challenge.user_id ?? ''),
      name: challenge.user_name ?? '',
      displayName: challenge.user_name ?? '',
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
    attestation: 'none',
    timeout: 60_000,
    excludeCredentials: (challenge.existing_credential_ids ?? []).map((id) => ({
      type: 'public-key' as const,
      id: toBuffer(id),
    })),
  }
  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null
  if (!credential) throw new Error('未能创建 Passkey')
  const response = credential.response as AuthenticatorAttestationResponse
  const transports =
    typeof response.getTransports === 'function' ? response.getTransports() : []
  return {
    challenge_id: challengeId,
    credential_id: toBase64Url(credential.rawId),
    attestation_object: toBase64Url(response.attestationObject),
    client_data_json: toBase64Url(response.clientDataJSON),
    transports,
    name,
  }
}

export async function getAssertion(
  challenge: WebAuthnAssertionChallengeReply,
  challengeId: string,
  currentPassword: string,
): Promise<VerifyWebAuthnAssertionRequest> {
  const assertion = await rawAssertion(
    challenge.challenge ?? '',
    challenge.rp_id ?? '',
    challenge.allow_credential_ids ?? [],
  )
  return {
    challenge_id: challengeId,
    credential_id: assertion.credentialId,
    authenticator_data: assertion.authenticatorData,
    client_data_json: assertion.clientDataJSON,
    signature: assertion.signature,
    current_password: currentPassword,
  }
}

export async function getLoginAssertion(
  challenge: string,
  rpId: string,
  allowCredentialIds: string[],
  challengeId: string,
): Promise<CompleteMFARequest> {
  const assertion = await rawAssertion(challenge, rpId, allowCredentialIds)
  return {
    challenge_id: challengeId,
    credential_id: assertion.credentialId,
    authenticator_data: assertion.authenticatorData,
    client_data_json: assertion.clientDataJSON,
    signature: assertion.signature,
  }
}

async function rawAssertion(challenge: string, rpId: string, allow: string[]) {
  if (!browserSupported()) throw new Error('当前浏览器不支持 Passkey，请使用 HTTPS 或更换浏览器')
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: toBuffer(challenge),
    rpId,
    userVerification: 'preferred',
    timeout: 60_000,
    allowCredentials: allow.map((id) => ({ type: 'public-key' as const, id: toBuffer(id) })),
  }
  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null
  if (!credential) throw new Error('未能完成 Passkey 验证')
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    credentialId: toBase64Url(credential.rawId),
    authenticatorData: toBase64Url(response.authenticatorData),
    clientDataJSON: toBase64Url(response.clientDataJSON),
    signature: toBase64Url(response.signature),
  }
}
