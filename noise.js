const curve = require('secp256k1')
const ecdh = require('./dh.js').dh
const crypto = require('crypto')
const assert = require('nanoassert')

module.exports = {
  generateKey
}

const SHA256_BYTES = 32
const ZERO = Buffer.alloc(0)
const PROTOCOL_TAG = Buffer.from('Noise_IK_25519_ChaChaPoly_BLAKE2b', 'utf8')
const PROLOGUE = Buffer.from('lightning', 'utf8')

module.exports.Initiator = class Initiator {
  constructor (staticKey, ephemeralKey) {
    this.static = staticKey ? generateKey(staticKey) : generateKey()
    this.ephemeral = ephemeralKey ? generateKey(ephemeralKey) : generateKey()

    this.chainingKey
    this.digest = Buffer.alloc(32)
    
    this.tempKey
    this.receiverEphemeral

    this.sender
    this.receiver
  }

  initialise (receivingNodeId) {
    accumulateDigest(this.digest, PROTOCOL_TAG)
    this.chainingKey = this.digest.slice()

    accumulateDigest(this.digest, PROLOGUE)
    accumulateDigest(this.digest, receivingNodeId)
  }

  one (receivingNodeKey) {
    const s = this.static.pub
    const e = this.ephemeral.pub

    accumulateDigest(this.digest, e)
    accumulateDigest(this.digest, s)

    const s = this.static.pub
    const e = this.ephemeral.pub

    const es = ecdh(receivingNodeId, this.ephemeral.priv)
    const ss = ecdh(receivingNodeId, this.static.priv)

    const inputKeyMaterial = Buffer.concat([es, ss])
    const hkdfResult = hkdf(this.chainingKey, inputKeyMaterial)

    this.chainingKey = hkdfResult[0]
    this.tempKey = hkdfResult[1]

    const ciphertext = encryptWithAD(this.tempKey, 0, this.digest, ZERO)
    accumulateDigest(this.digest, ciphertext)

    const result = Buffer.concat([Buffer.alloc(1), e, s, ciphertext])
    return result
  }

  two (buf) {
    const version = buf.slice(0, 1)
    const ciphertext = buf.slice(1, 50)
    const tag = buf.slice(50)

    const re = decryptWithAD(this.tempKey, 0, this.digest, ciphertext)

    accumulateDigest(this.digest, ciphertext)

    const ee = ecdh(re, this.ephemeral.priv)
    const se = ecdh(re, this.static.priv)

    const inputKeyMaterial = Buffer.concat([ee, se])
    const hkdfResult = hkdf(this.chainingKey, inputKeyMaterial)

    this.chainingKey = hkdfResult[0]
    this.tempKey = hkdfResult[1]

    const plaintext = decryptWithAD(this.tempKey, 1, this.digest, tag)
    accumulateDigest(this.digest, ciphertext)

    const finalKeys = hkdf(this.chainingKey, ZERO)
    this.receiver = this.finalKey(finalKeys[0])
    this.sender = this.finalKey(finalKeys[1])
  }

  send (message) {
    if (!message instanceof Uint8Array) return new Error('message should be serialized into a buffer')
    let lengthBuf = Buffer.alloc(2)
    lengthBuf.writeUInt16BE(message.byteLength)

    const header = encryptWithAD(this.sender.key, this.sender.nonce, ZERO, lengthBuf)
    this.sender.increment()

    const body = encryptWithAD(this.sender.key, this.sender.nonce, ZERO, message)
    this.sender.increment()

    return Buffer.concat([header, body])
  }

  receive (buf) {
    const header = buf.slice(0, 18)
    const body = buf.slice(18)

    const length = decryptWithAD(this.receiver.key, this.receiver.nonce, ZERO, header)
    this.receiver.increment()

    const message = decryptWithAD(this.receiver.key, this.receiver.nonce, ZERO, body)
    this.receiver.increment()
    
    if (message.byteLength !== length.readUInt16BE()) return new Error('invalid message: length not as expected')
  
    return message
  }

  finalKey (key) {
    const self = this

    const obj = {
      key,
      nonce: 0
    }

    obj.increment = function () {
      this.nonce++

      if (this.nonce >= 1000) {
        const res = hkdf(self.chainingKey, this.key)
        self.chainingKey = res[0]
        this.key = res[1]
        this.nonce = 0
      }
    }

    return obj
  }
}

module.exports.Responder = class Responder {
  constructor (staticKeyPair) {
    this.static = staticKeyPair || generateKey()
    this.ephemeral
    
    this.chainingKey
    this.digest = Buffer.alloc(32)
    
    this.tempKey
    this.initiatorEphemeral

    this.sender
    this.receiver
  }
  
  initialise () {
    accumulateDigest(this.digest, PROTOCOL_TAG)
    this.chainingKey = this.digest.slice()

    accumulateDigest(this.digest, PROLOGUE)
    accumulateDigest(this.digest, this.static.pub.serializeCompressed())
  }

  one (buf) {
    const version = buf.slice(0, 1)
    const re = buf.slice(1, 33)
    const rs = buf.slice(33, 65)
    const ciphertext = buf.slice(65)

    this.initiatorEphemeral = re
    this.initiatorStatic = rs

    accumulateDigest(this.digest, re)
    accumulateDigest(this.digest, rs)

    const es = ecdh(re, this.static.priv)
    const ss = ecdh(rs, this.static.priv)
    
    const inputKeyMaterial = Buffer.concat([es, ss])
    const hkdfResult = hkdf(this.chainingKey, inputKeyMaterial)

    this.chainingKey = hkdfResult[0]
    this.tempKey = hkdfResult[1]

    const plaintext = decryptWithAD(this.tempKey, 0, this.digest, ciphertext)
    accumulateDigest(this.digest, ciphertext)
  }

  two (ephemeralPriv) {
    this.ephemeral = generateKey(ephemeralPriv)

    const e = this.ephemeral.pub
    const ciphertext = encryptWithAD(this.tempKey, 0, this.digest, e)

    accumulateDigest(this.digest, ciphertext)

    const ee = ecdh(this.initiatorEphemeral, this.ephemeral.priv)
    const se = ecdh(this.initiatorStatic, this.ephemeral.priv)

    const inputKeyMaterial = Buffer.concat([ee, se])
    const hkdfResult = hkdf(this.chainingKey, inputKeyMaterial)

    this.chainingKey = hkdfResult[0]
    this.tempKey = hkdfResult[1]

    const tag = encryptWithAD(this.tempKey, 1, this.digest, ZERO)
    
    const finalKeys = hkdf(this.chainingKey, ZERO)
    this.receiver = this.finalKey(finalKeys[0])
    this.sender = this.finalKey(finalKeys[1])

    const result = Buffer.concat([Buffer.alloc(1), ciphertext, tag])
    return result
  }

  send (message) {
    if (!message instanceof Uint8Array) return new Error('message should be serialized into a buffer')
    let lengthBuf = Buffer.alloc(2)
    lengthBuf.writeUInt16BE(message.byteLength)

    const header = encryptWithAD(this.sender.key, this.sender.nonce, ZERO, lengthBuf)
    this.sender.increment()

    const body = encryptWithAD(this.sender.key, this.sender.nonce, ZERO, message)
    this.sender.increment()

    return Buffer.concat([header, body])
  }

  receive (buf) {
    const header = buf.slice(0, 18)
    const body = buf.slice(18)

    const length = decryptWithAD(this.receiver.key, this.receiver.nonce, ZERO, header)
    this.receiver.increment()

    const message = decryptWithAD(this.receiver.key, this.receiver.nonce, ZERO, body)
    this.receiver.increment()

    if (message.byteLength !== length.readUInt16BE()) return new Error('invalid message: length not as expected')

    return message
  }

  finalKey (key) {
    const self = this

    const obj = {
      key,
      nonce: 0
    }

    obj.increment = function () {
      this.nonce++

      if (this.nonce >= 1000) {
        const res = hkdf(self.chainingKey, this.key)
        self.chainingKey = res[0]
        this.key = res[1]
        this.nonce = 0
      }
    }

    return obj
  }
}

function accumulateDigest (digest, input) {
  const toHash = Buffer.concat([digest, input])
  sodium.crypto_generichash(digest, toHash)
}

function generateKey (privKey) {
  const keyPair = {}

  keyPair.priv = privKey || newPrivKey()
  keyPair.pub = curve.publicKeyCreate(keyPair.priv)

  keyPair.pub.serializeCompressed = function () {
    return Buffer.from(curve.publicKeyConvert(this))
  }

  return keyPair

  function newPrivKey () {
    let key
    do {
      key = crypto.randomBytes(32)
    } while (!curve.privateKeyVerify(key))
    return key
  }
}

function encryptWithAD (key, counter, additionalData, plaintext) {
  // for our purposes, additionalData will always be a pubkey so we encode from hex 
  if (!additionalData instanceof Uint8Array) additionalData = Buffer.from(additionalData, 'hex')
  if (!plaintext instanceof Uint8Array) plaintext = Buffer.from(plaintext, 'hex')

  const counterBuf = Buffer.alloc(12)
  writeInt64LE(counter, counterBuf, 4)
  
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, counterBuf, {
    authTagLength: 16
  })

  cipher.setAAD(additionalData, { plaintextLength: plaintext.length })

  const head = cipher.update(plaintext)
  const final = cipher.final()
  const encrypted = Buffer.concat([head, final])
  const tag = cipher.getAuthTag('hex')

  const result = Buffer.concat([encrypted, tag])

  return result
}

function decryptWithAD (key, counter, additionalData, data) {
  // for our purposes, additionalData will always be a pubkey so we encode from hex 
  if (!additionalData instanceof Uint8Array) additionalData = Buffer.from(additionalData, 'hex')
  if (!data instanceof Uint8Array) data = Buffer.from(data, 'hex')

  const ciphertext = data.slice(0, data.byteLength - 16)
  const receivedTag = data.slice(data.byteLength - 16)

  const decrypted = encryptWithAD(key, counter, additionalData, ciphertext)
  const plaintext = decrypted.slice(0, decrypted.byteLength - 16)

  const checkTag = encryptWithAD(key, counter, additionalData, plaintext)
  const tag = checkTag.slice(checkTag.byteLength - 16)

  // if (Buffer.compare(receivedTag, tag) !== 0) throw new Error('MAC could not be verified')

  return plaintext
}

function hkdf (salt, inputKeyMaterial, info = '', length = 64) {
  const pseudoRandomKey = hkdfExtract(salt, inputKeyMaterial)
  const result = hkdfExpand(pseudoRandomKey, info, length)

  const [ k1, k2 ] = [ result.slice(0, 32), result.slice(32)]
  
  return [ k1, k2 ]
  
  function hkdfExtract (salt, inputKeyMaterial) {
    return hmacDigest(salt, inputKeyMaterial)
  }

  function hkdfExpand(key, info = '', length = 64) {
    const T = [Buffer.from('')]
    const lengthRatio = length / SHA256_BYTES

    for (let i = 0; i < lengthRatio; i++) {
      const toHash = new Uint8Array(T[i].byteLength + info.length + 1)
      
      toHash.set(T[i])
      let offset = T[i].byteLength

      if (info.length) {
        const infoBuf = Buffer.from(info)
        toHash.set(infoBuf, offset)
        offset += infoBuf.byteLength
      }

      toHash[offset] = i + 1

      T[i + 1] = hmacDigest(key, toHash)
    }

    const result = Buffer.concat(T.slice(1))
    assert(result.byteLength === length, 'key expansion failed, length not as expected')

    return result
  }
}

function hmacDigest (key, input) {
  const hmac = crypto.createHmac('blake2b512', key)
  hmac.update(input)

  return hmac.digest()
}

function writeInt64LE (value, buf, offset) {
  if (!buf) buf = Buffer.alloc(8)
  if (!offset) offset = 0
  number = BigInt(value)

  let lo = Number(number & 0xffffffffn)
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8

  let hi = Number(number >> 32n & 0xffffffffn)
  buf[offset++] = hi
  hi = hi >> 8  
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8  
  buf[offset++] = hi
  hi = hi >> 8

  return buf
}

function paddedLength (buf, interval) {
  if (buf.byteLength === 0) return 0
  return Math.ceil(buf.byteLength / interval) * 16
}
