const DB_NAME = 'alparts-crypto';
const STORE_NAME = 'keys';

async function getDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function saveKey(keyId: string, key: CryptoKey | string): Promise<void> {
  const db = await getDb();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  const store = tx.objectStore(STORE_NAME);

  if (typeof key === 'string') {
    store.put(key, keyId);
  } else {
    const exported = await crypto.subtle.exportKey('jwk', key);
    store.put(JSON.stringify(exported), keyId);
  }

  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadKey(keyId: string): Promise<string | null> {
  const db = await getDb();
  const tx = db.transaction(STORE_NAME, 'readonly');
  const store = tx.objectStore(STORE_NAME);
  const request = store.get(keyId);

  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

// Generate RSA-OAEP key pair for device
export async function generateDeviceKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true, // extractable
    ['encrypt', 'decrypt'],
  );

  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  const publicKeyPem = jwkToPem(publicKeyJwk, 'PUBLIC');
  const privateKeyStr = JSON.stringify(privateKeyJwk);

  await saveKey('device-private-key', privateKeyStr);

  return { publicKey: publicKeyPem, privateKey: privateKeyStr };
}

// Get stored private key
export async function getDevicePrivateKey(): Promise<string | null> {
  return loadKey('device-private-key');
}

// Check if device key exists
export async function hasDeviceKey(): Promise<boolean> {
  const key = await loadKey('device-private-key');
  return key !== null;
}

// Generate AES-256-GCM channel key
export async function generateChannelKey(): Promise<string> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const exported = await crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(exported);
}

// Encrypt message with channel key
export async function encryptMessage(content: string, channelKeyJwk: string): Promise<{ encrypted: string; nonce: string }> {
  const key = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(channelKeyJwk),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );

  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    data,
  );

  return {
    encrypted: arrayBufferToBase64(encrypted),
    nonce: arrayBufferToBase64(nonce),
  };
}

// Decrypt message with channel key
export async function decryptMessage(encryptedBase64: string, nonceBase664: string, channelKeyJwk: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(channelKeyJwk),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  const encrypted = base64ToArrayBuffer(encryptedBase64);
  const nonce = base64ToArrayBuffer(nonceBase664);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    encrypted,
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

// Encrypt channel key with device public key
export async function encryptChannelKeyForDevice(channelKeyJwk: string, devicePublicKeyPem: string): Promise<string> {
  const publicKeyJwk = pemToJwk(devicePublicKeyPem);
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicKeyJwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );

  const encoder = new TextEncoder();
  const data = encoder.encode(channelKeyJwk);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    data,
  );

  return arrayBufferToBase64(encrypted);
}

// Decrypt channel key with device private key
export async function decryptChannelKey(encryptedKeyBase64: string, privateKeyJwk: string): Promise<string> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(privateKeyJwk),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  );

  const encrypted = base64ToArrayBuffer(encryptedKeyBase64);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    encrypted,
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

// Helper functions
function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

function jwkToPem(jwk: JsonWebKey, type: 'PUBLIC' | 'PRIVATE'): string {
  const base64 = btoa(JSON.stringify(jwk));
  return `-----BEGIN ${type} KEY-----\n${base64}\n-----END ${type} KEY-----`;
}

function pemToJwk(pem: string): JsonWebKey {
  const base64 = pem
    .replace(/-----BEGIN.*-----/, '')
    .replace(/-----END.*-----/, '')
    .replace(/\s/g, '');
  return JSON.parse(atob(base64));
}
