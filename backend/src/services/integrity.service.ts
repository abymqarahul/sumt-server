import { GoogleAuth } from 'google-auth-library';
import type { Env } from '../config/env.js';

export interface IntegrityResult {
  checked: boolean;
  passed: boolean;
  summary: string;
}

/**
 * Optional Google Play Integrity verification (classic request, nonce = sha256(SPKI) base64url).
 * INTEGRITY_MODE=off     → not called.
 * INTEGRITY_MODE=log     → verdict stored on the installation, never blocks.
 * INTEGRITY_MODE=enforce → registration rejected unless the device meets basic device integrity.
 * Requires PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON (a Google Cloud service account linked in Play Console).
 * Note: APKs distributed outside Google Play report appRecognitionVerdict=UNRECOGNIZED_VERSION, so
 * enforce mode checks the *device* verdict only.
 */
export class IntegrityVerifier {
  private auth: GoogleAuth | null = null;

  constructor(private readonly env: Env) {
    if (env.INTEGRITY_MODE !== 'off' && env.PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON) {
      this.auth = new GoogleAuth({
        credentials: JSON.parse(env.PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON),
        scopes: ['https://www.googleapis.com/auth/playintegrity'],
      });
    }
  }

  get mode() {
    return this.env.INTEGRITY_MODE;
  }

  async verify(token: string | undefined, expectedNonce: string): Promise<IntegrityResult> {
    if (this.env.INTEGRITY_MODE === 'off') return { checked: false, passed: true, summary: 'off' };
    if (!this.auth) return { checked: false, passed: this.env.INTEGRITY_MODE !== 'enforce', summary: 'not_configured' };
    if (!token) return { checked: true, passed: false, summary: 'missing_token' };
    try {
      const client = await this.auth.getClient();
      const res = await client.request<{ tokenPayloadExternal?: any }>({
        url: `https://playintegrity.googleapis.com/v1/${encodeURIComponent(this.env.ANDROID_PACKAGE_NAME)}:decodeIntegrityToken`,
        method: 'POST',
        data: { integrity_token: token },
        timeout: 10_000,
      });
      const p = res.data.tokenPayloadExternal ?? {};
      const nonceOk = p.requestDetails?.nonce === expectedNonce;
      const pkgOk = p.requestDetails?.requestPackageName === this.env.ANDROID_PACKAGE_NAME;
      const device: string[] = p.deviceIntegrity?.deviceRecognitionVerdict ?? [];
      const app: string = p.appIntegrity?.appRecognitionVerdict ?? 'UNEVALUATED';
      const deviceOk = device.includes('MEETS_DEVICE_INTEGRITY') || device.includes('MEETS_BASIC_INTEGRITY');
      return {
        checked: true,
        passed: nonceOk && pkgOk && deviceOk,
        summary: `device=${device.join('|') || 'NONE'};app=${app};nonce=${nonceOk};pkg=${pkgOk}`,
      };
    } catch (err) {
      return { checked: true, passed: false, summary: `error:${(err as Error).message.slice(0, 120)}` };
    }
  }
}
