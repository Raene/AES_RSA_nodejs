const path = require("path");
const NodeRSA = require("node-rsa");
const crypto = require("crypto");
const fs = require("fs");
const aesWrapper = require("./crypt");
const rsaWrapper = {};
// open and closed keys generation method
rsaWrapper.generate = direction => {
  let key = new NodeRSA();
  // 2048 — key length, 65537 open exponent
  key.generateKeyPair(2048, 65537);
  //save keys as pem line in pkcs8
  fs.writeFileSync(
    path.resolve(__dirname, "keys", direction + ".private.pem"),
    key.exportKey("pkcs8-private-pem")
  );
  fs.writeFileSync(
    path.resolve(__dirname, "keys", direction + ".public.pem"),
    key.exportKey("pkcs8-public-pem")
  );
  return true;
};

rsaWrapper.encrypt = (publicKey, message) => {
  let enc = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.RSA_PKCS1_OAEP_PADDING
    },
    Buffer.from(message)
  );
  return enc.toString("base64");
};
// descrypting RSA, using padding OAEP, with nodejs crypto:
rsaWrapper.decrypt = (privateKey, message) => {
  let enc = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.RSA_PKCS1_OAEP_PADDING
    },
    Buffer.from(message, "base64")
  );
  return enc.toString();
};
// Loading RSA keys from files to variables:
rsaWrapper.initLoadServerKeys = basePath => {
  rsaWrapper.serverPub = fs.readFileSync(
    path.resolve(basePath, "keys", "IOTserver.public.pem")
  );
  rsaWrapper.serverPrivate = fs.readFileSync(
    path.resolve(basePath, "keys", "IOTserver.private.pem")
  );
};
// Run RSA encryption test scenario. Message is encrypted, log on console in base64 format and message is decrypted and log on console.
rsaWrapper.serverExampleEncrypt = encryptData => {
  console.log("Server public encrypting", encryptData);
  let enc = rsaWrapper.encrypt(rsaWrapper.serverPub, encryptData);
  console.log("Server private encrypting …\n");
  console.log("Encrypted RSA string ‘, ‘\n", enc);
  let dec = rsaWrapper.decrypt(rsaWrapper.serverPrivate, enc);
  console.log("Decrypted RSA string …");
  console.log(Buffer.from(dec, "hex"));

  let encrypted = aesWrapper.encrypt(Buffer.from(dec, "hex"), "bobby");
  console.log(aesWrapper.decrypt(Buffer.from(dec, "hex"), encrypted));
};
let key = aesWrapper.key().toString("hex");
rsaWrapper.initLoadServerKeys(__dirname);
rsaWrapper.serverExampleEncrypt(key);
// rsaWrapper.generate("IOTserver");
