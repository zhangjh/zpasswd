import sodium from 'libsodium-wrappers-sumo';
import { KEY_BYTES } from './kdf';

export interface SealedBox {
  nonce: string; // base64
  ciphertext: string; // base64
}

function b64encode(buf: Uint8Array): string {
  return sodium.to_base64(buf, sodium.base64_variants.ORIGINAL);
}
function b64decode(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}

/**
 * 信封加密：用 KEK 包裹 DEK。换主密码时只需重包 DEK，不用重加密全库。
 */
export async function wrapDek(kek: Uint8Array, dek: Uint8Array): Promise<SealedBox> {
  await sodium.ready;
  assertKey(kek, 'kek');
  assertKey(dek, 'dek');
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(dek, null, null, nonce, kek);
  return { nonce: b64encode(nonce), ciphertext: b64encode(ciphertext) };
}

export async function unwrapDek(kek: Uint8Array, box: SealedBox): Promise<Uint8Array> {
  await sodium.ready;
  assertKey(kek, 'kek');
  const nonce = b64decode(box.nonce);
  const ciphertext = b64decode(box.ciphertext);
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, kek);
}

/** 条目加密：明文 JSON -> {nonce, ciphertext}（base64），存 IndexedDB / 服务端。 */
export async function encryptItem(dek: Uint8Array, plaintext: string): Promise<SealedBox> {
  await sodium.ready;
  assertKey(dek, 'dek');
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    sodium.from_string(plaintext),
    null,
    null,
    nonce,
    dek,
  );
  return { nonce: b64encode(nonce), ciphertext: b64encode(ciphertext) };
}

/** 条目解密：篡改/错 key 直接抛异常，调用方按"数据损坏"处理并提示用户。 */
export async function decryptItem(dek: Uint8Array, box: SealedBox): Promise<string> {
  await sodium.ready;
  assertKey(dek, 'dek');
  const nonce = b64decode(box.nonce);
  const ciphertext = b64decode(box.ciphertext);
  const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, dek);
  return sodium.to_string(plain);
}

function assertKey(k: Uint8Array, name: string): void {
  if (k.length !== KEY_BYTES) throw new Error(`${name} must be ${KEY_BYTES} bytes`);
}
