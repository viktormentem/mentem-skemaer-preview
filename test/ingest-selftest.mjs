// F1-4 web-POST verifikation — kontrakt-konformans (ingest-kontrakt-v1 §2.2/§4/§5)
// Syntetisk X25519-modtagerpar (ALDRIG rigtige nøgler) + SYN--pseudonym (§8.7).
import { webcrypto } from 'node:crypto';
const subtle = webcrypto.subtle;

const core = await import('../mentem-skema-core.js');
const { byggIngestSubmitBody, byggIngestKonvolut, buildPayloadCSD, PINNED_PUBKEY, PINNED_KEY_ID,
        INGEST_ENVELOPE_VERSION } = core;

let pass = 0, fail = 0;
function assert(cond, name) {
  if (cond) { pass++; console.log('  PASS', name); }
  else { fail++; console.log('  FAIL', name); }
}
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const b64d = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// 1) Syntetisk ingest-modtagerpar (X25519)
const pair = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
const pubRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
const ingestPubB64 = b64u(pubRaw);
const keyIdHash = new Uint8Array(await subtle.digest('SHA-256', pubRaw));
const ingestKeyId = Buffer.from(keyIdHash.slice(0, 4)).toString('hex');
assert(ingestKeyId !== PINNED_KEY_ID, 'syntetisk keyId != 8aa536a1');

// 2) Realistisk CSD-payload m. æøå + safetyFlag (web's nuværende keys)
const entries = [
  { date: '2026-06-05', bedtime: '23:15', lightsOut: '23:30', sleepLatencyMin: 45,
    awakeningsCount: 2, awakeningsMin: 30, finalAwake: '06:30', outOfBed: '06:45',
    quality: 2, naps: 'Nej', medication: 'Kaffe kl. 8 — én kop', safetyFlag: 'Nej', savedAt: '2026-06-05T07:00:00Z' },
  { date: '2026-06-06', bedtime: '23:00', lightsOut: '23:05', sleepLatencyMin: 20,
    awakeningsCount: 1, awakeningsMin: 10, finalAwake: '06:15', outOfBed: '06:20',
    quality: 3, naps: 'Nej', medication: 'Intet', safetyFlag: 'Ja',
    safetyNote: 'Var tæt på at falde i søvn bag rattet på vej hjem — kørte ind til siden. Æøå-test.', savedAt: '2026-06-06T07:30:00Z' },
];
const payload = buildPayloadCSD(entries, { startedAt: '2026-06-05', plannedDays: 14, forloebId: 'v1.SYN-VERATEST.9999999999.e30.c2ln', contentVersion: 1 });

// 3) Byg submit-body (kontrakt §2.2)
const SYN_TOKEN = 'v1.SYN-VERATEST.9999999999.e30.c2ln';
const uuid = webcrypto.randomUUID();
const body = await byggIngestSubmitBody({
  token: SYN_TOKEN, payloadObj: payload, ingestPubB64, ingestKeyId,
  submissionUUID: uuid, schemaType: 'soevndagbog', clientUA: 'web',
});
assert(body.token === SYN_TOKEN, '§2.2 token ordret');
assert(body.envelopeVersion === 1 && INGEST_ENVELOPE_VERSION === 1, '§2.2 envelopeVersion=1');
assert(body.submissionUUID === uuid, '§2.2 submissionUUID');
assert(body.schemaType === 'soevndagbog', '§2.2 schemaType');
assert(typeof body.ciphertext === 'string', '§2.2 ciphertext er JSON-STRENG');
assert(body.size === body.ciphertext.length, '§2.2 size = ciphertext.length');
assert(body.ciphertext.length < 262144, 'size < 256KB-cap');

// 4) Container (kontrakt §4): 5 krævede felter + korrekte længder + keyId
const container = JSON.parse(body.ciphertext);
for (const f of ['ephemeralPublicKey', 'encryptedData', 'nonce', 'tag', 'salt'])
  assert(typeof container[f] === 'string' && container[f].length > 0, `§4 container.${f}`);
assert(b64d(container.ephemeralPublicKey).length === 32, '§4 efemer pub = 32B');
assert(b64d(container.nonce).length === 12, '§4 nonce = 12B');
assert(b64d(container.tag).length === 16, '§4 tag = 16B');
assert(b64d(container.salt).length === 32, '§4 salt = 32B');
assert(container.keyId === ingestKeyId, '§4 keyId stemplet = ingest-keyId');
assert(container.keyId !== '8aa536a1', '§4 keyId != journal-nøglen (T4)');
assert(!new RegExp('safetyFlag|sleepDiary|Æøå').test(body.ciphertext.replace(/"(ephemeralPublicKey|encryptedData|nonce|tag|salt)":"[^"]*"/g, '')), 'ingen klartekst-lækage i envelope');

// 5) Dekryptér per kontrakt §4 (uafhængig impl — IKKE web-koden)
const ephPub = await subtle.importKey('raw', b64d(container.ephemeralPublicKey), { name: 'X25519' }, false, []);
const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: ephPub }, pair.privateKey, 256));
const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
const keyBits = await subtle.deriveBits(
  { name: 'HKDF', hash: 'SHA-256', salt: b64d(container.salt), info: new TextEncoder().encode('TherapyCopilot-E2E-Export-v1') }, ikm, 256);
const aesKey = await subtle.importKey('raw', keyBits, { name: 'AES-GCM' }, false, ['decrypt']);
const combined = Buffer.concat([b64d(container.encryptedData), b64d(container.tag)]);
const plain = await subtle.decrypt({ name: 'AES-GCM', iv: b64d(container.nonce) }, aesKey, combined);
const konvolut = JSON.parse(new TextDecoder().decode(plain));

// 6) Konvolut-konformans (kontrakt §5 + §6)
assert(konvolut.schemaVersion === 1, '§5 schemaVersion=1');
assert(konvolut.schemaType === 'soevndagbog', '§5 schemaType');
assert(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(konvolut.clientTimestamp), '§5 clientTimestamp ISO-8601 UDEN fraktioner');
assert(konvolut.respondentPseudonym === null, '§5 respondentPseudonym=null (individ)');
assert(konvolut.clientUA === 'web', '§6 clientUA="web"');
assert(konvolut.data && konvolut.data.sleepDiary && konvolut.data.sleepDiary.length === 2, '§5 data.sleepDiary (2 nætter)');
assert(konvolut.data.sleepDiary[1].safetyFlag === 'Ja', 'sleepDiary[].safetyFlag intakt (§8.3-kæden)');
assert(konvolut.data.sleepDiary[1].safetyNote.includes('Æøå-test'), 'æøå byte-intakt gennem encrypt→decrypt');
assert(konvolut.data.meta && konvolut.data.meta.periodCompleted === 2, 'payload.meta intakt');

// 7) Nøgle-guards + token-format-guard
async function expectThrow(args, errName, label) {
  try { await byggIngestSubmitBody(args); assert(false, label); }
  catch (e) { assert(e.message === errName, label + ` (${e.message})`); }
}
await expectThrow({ token: SYN_TOKEN, payloadObj: payload, ingestPubB64: PINNED_PUBKEY, ingestKeyId, submissionUUID: uuid }, 'ingest_key_guard', 'GUARD: journal-PUBKEY afvist');
await expectThrow({ token: SYN_TOKEN, payloadObj: payload, ingestPubB64, ingestKeyId: '8aa536a1', submissionUUID: uuid }, 'ingest_key_guard', 'GUARD: journal-keyId afvist');
await expectThrow({ token: 'abcdef0123456789abcdef0123456789', payloadObj: payload, ingestPubB64, ingestKeyId, submissionUUID: uuid }, 'ingest_token_format', 'GUARD: legacy 32-hex-token afvist');
await expectThrow({ token: SYN_TOKEN, payloadObj: payload, ingestPubB64: '', ingestKeyId, submissionUUID: uuid }, 'ingest_key_missing', 'GUARD: tom pubkey afvist');
await expectThrow({ token: SYN_TOKEN, payloadObj: payload, ingestPubB64, ingestKeyId, submissionUUID: '' }, 'ingest_uuid_missing', 'GUARD: manglende UUID afvist');

// 8) Tamper-test: flip én byte i encryptedData → decrypt SKAL fejle
const tampered = b64d(container.encryptedData); tampered[0] ^= 0xff;
let tamperOk = false;
try {
  await subtle.decrypt({ name: 'AES-GCM', iv: b64d(container.nonce) }, aesKey, Buffer.concat([tampered, b64d(container.tag)]));
} catch (e) { tamperOk = true; }
assert(tamperOk, 'tamper afvist (GCM-tag)');

console.log(`\nRESULTAT: ${pass} PASS / ${fail} FAIL`);
process.exit(fail ? 1 : 0);
