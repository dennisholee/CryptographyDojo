const crypto = require('crypto');
const {Buffer} = require('buffer');

let dump = `
{"SecretKey" : "VSGJAOLVy8orB1CSpkgiSALaOxpz29CDIzYldOoZ0F4=",
 "IV"        : "IE618XeGTrGisyN5",
 "Plain"     : "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm",
 "Encrypted" : "IHln/UBRhGTxO1m/dwGYZ4TK644sz4fEgJ0Mvi4Vu8GXjM7P3Flt+4O+gScGxwt2phBAyQ18mJb0RZxBUrJ1cHkZBG1FTuyDKfCNxa/55PQOmx6WiEDtwQYAkLwkKRkdtUiluCYYIxI=",
 "Decrypted" : "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm"}
`

//------------------------------------------------------------------------------
// Decrypt from Java code
//------------------------------------------------------------------------------
let jsonDump = JSON.parse(dump);
console.log(jsonDump);

let keyRaw = Buffer.from(jsonDump['SecretKey'], 'base64');
let ivRaw = Buffer.from(jsonDump['IV'], 'base64');


let decipher = crypto.createDecipheriv("aes-256-gcm", keyRaw, ivRaw, {authTagLength: 16});

let encryptedData = jsonDump['Encrypted'];
let encryptedRaw = Buffer.from(encryptedData, 'base64');

let tagRaw = encryptedRaw.subarray(encryptedRaw.length - 16);
let encTextRaw = encryptedRaw.subarray(0, encryptedRaw.length - 16);

decipher.setAuthTag(tagRaw);

let decrypted = decipher.update(encTextRaw); 
decrypted += decipher.final("utf8");
console.log(decrypted)

