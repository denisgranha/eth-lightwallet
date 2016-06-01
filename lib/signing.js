var Transaction = require("ethereumjs-tx")
var util = require("ethereumjs-util")

signTx = function (keystore, pwDerivedKey, rawTx, signingAddress, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = keystore.defaultHdPathString;
  }

  rawTx = util.stripHexPrefix(rawTx);
  signingAddress = util.stripHexPrefix(signingAddress);

  var txCopy = new Transaction(new Buffer(rawTx, 'hex'));

  var privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey, hdPathString);

  txCopy.sign(new Buffer(privKey, 'hex'));
  privKey = '';

  return txCopy.serialize().toString('hex');
};

module.exports.signTx = signTx;

signMsg = function (keystore, pwDerivedKey, rawMsg, signingAddress, hdPathString) {
  var msgHash = util.addHexPrefix(util.sha3(rawMsg).toString('hex'));
  return this.signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress, hdPathString);
};

module.exports.signMsg = signMsg;

signMsgHash = function (keystore, pwDerivedKey, msgHash, signingAddress, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = keystore.defaultHdPathString;
  }

  signingAddress = util.stripHexPrefix(signingAddress);

  var privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey, hdPathString);

  return util.ecsign(new Buffer(util.stripHexPrefix(msgHash), 'hex'), new Buffer(privKey, 'hex'));
};

module.exports.signMsgHash = signMsgHash;

recoverAddress = function (rawMsg, v, r, s) {

  var msgHash = util.sha3(rawMsg);

  return util.pubToAddress(util.ecrecover(msgHash, v, r, s));
};

module.exports.recoverAddress = recoverAddress;

function pad_with_zeroes(number, length){
  var my_string = '' + number;
  while (my_string.length < length) {
    my_string = '0' + my_string;
  }
  return my_string;
}

concatSig = function (signature) {
  var v = signature.v;
  var r = signature.r;
  var s = signature.s;
  r = util.fromSigned(r);
  s = util.fromSigned(s);
  v = util.bufferToInt(v);
  r = pad_with_zeroes(util.toUnsigned(r).toString('hex'), 64);
  s = pad_with_zeroes(util.toUnsigned(s).toString('hex'), 64);
  v = util.stripHexPrefix(util.intToHex(v));
  return util.addHexPrefix(r.concat(s, v).toString("hex"));
};

module.exports.concatSig = concatSig;
