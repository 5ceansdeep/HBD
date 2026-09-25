// 사용법: node encrypt-letter.js <비밀번호>
// letter.js(깃에 안 올라가는 편지 원문)를 비밀번호로 암호화해 letter.enc.json을 만든다.
// letter.enc.json은 비밀번호 없이는 못 읽으니 GitHub에 올려도 됨.
const fs = require('fs');
const { webcrypto } = require('crypto'), { subtle } = webcrypto, getRandomValues = a => webcrypto.getRandomValues(a);

(async () => {
  const pw = process.argv[2];
  if (!pw) throw new Error('비밀번호를 적어주세요: node encrypt-letter.js <비밀번호>');
  const text = fs.readFileSync('letter.js', 'utf8').match(/`([\s\S]*)`/)[1];
  const iter = 310000, salt = getRandomValues(new Uint8Array(16)), iv = getRandomValues(new Uint8Array(12));
  const base = await subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const data = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text)));
  const b64 = a => Buffer.from(a).toString('base64');
  fs.writeFileSync('letter.enc.json', JSON.stringify({ iter, salt: b64(salt), iv: b64(iv), data: b64(data) }));
  console.log(`letter.enc.json 생성 (${text.length}자)`);
})();
