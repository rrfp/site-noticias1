const sodium = require('libsodium-wrappers');
(async()=>{ await sodium.ready; })();


function getKey(){
if(!process.env.DATA_KEY) throw new Error('DATA_KEY não definido');
return sodium.from_base64(process.env.DATA_KEY, sodium.base64_variants.ORIGINAL);
}


function encryptText(plain){
const key = getKey();
const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
const cipher = sodium.crypto_secretbox_easy(sodium.from_string(plain), nonce, key);
return `${sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL)}:${sodium.to_base64(cipher, sodium.base64_variants.ORIGINAL)}`;
}


function decryptText(stored){
const key = getKey();
const [nonce_b64, cipher_b64] = stored.split(':');
const nonce = sodium.from_base64(nonce_b64, sodium.base64_variants.ORIGINAL);
const cipher = sodium.from_base64(cipher_b64, sodium.base64_variants.ORIGINAL);
const plain = sodium.crypto_secretbox_open_easy(cipher, nonce, key);
return sodium.to_string(plain);
}


module.exports = { encryptText, decryptText };