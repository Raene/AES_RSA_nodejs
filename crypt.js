var crypto = require("crypto");
let iv = crypto.randomBytes(16);
const aesWrapper = {
  algorithm: "aes-192-cbc",
  password: "Password used to generate key",
  key: function() {
    return crypto.scryptSync(this.password, "salt", 24);
  },
  cipher: function(key) {
    return crypto.createCipheriv(this.algorithm, key, iv);
  },
  decipher: function(key) {
    return crypto.createDecipheriv(this.algorithm, key, iv);
  }
};

aesWrapper.encrypt = function(key, text) {
  let cipher = this.cipher(key);
  let encrypted = "";
  cipher.on("readable", () => {
    let chunk;
    while (null !== (chunk = cipher.read())) {
      encrypted += chunk.toString("hex");
    }
  });
  cipher.on("end", () => {
    console.log("AES Encryption");
  });

  cipher.write(text);
  cipher.end();
  return encrypted;
};

aesWrapper.decrypt = function(key, encrypted) {
  let decipher = this.decipher(key);
  let decrypted = "";
  decipher.on("readable", () => {
    while (null !== (chunk = decipher.read())) {
      decrypted += chunk.toString("utf8");
    }
  });
  decipher.on("end", () => {
    console.log("Decrypted");
    // Prints: some clear text data
  });

  // Encrypted with same algorithm, key and iv.
  decipher.write(encrypted, "hex");
  decipher.end();
  return decrypted;
};
module.exports = aesWrapper;
