/**
 * Generates every secret the backend needs. Run once, paste the values into Railway → Variables.
 *   npm run build && npm run keys:generate
 * Never commit the output.
 */
import crypto from 'node:crypto';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
const pub = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const rnd = () => crypto.randomBytes(48).toString('base64url');

console.log('# ---- Railway variables (secret) ----');
console.log(`LICENSE_SIGNING_PRIVATE_KEY=${priv}`);
console.log(`ACTIVATION_KEY_PEPPER=${rnd()}`);
console.log(`JWT_ACCESS_SECRET=${rnd()}`);
console.log(`DOWNLOAD_TICKET_SECRET=${rnd()}`);
console.log('');
console.log('# ---- Public (safe to embed in the customer Android app) ----');
console.log(`LICENSE_PUBLIC_KEY=${pub}`);
