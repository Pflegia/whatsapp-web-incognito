//
// Noise & Signal protocol handling
//

var MultiDevice = {};

var originalImportKey = crypto.subtle.importKey;

MultiDevice.initialize = function () {
  MultiDevice.readKey = null;
  MultiDevice.readKeyImported = null;
  MultiDevice.writeKey = null;
  MultiDevice.writeKeyImported = null;
  MultiDevice.readCounter = 0;
  MultiDevice.writeCounter = 0;
  MultiDevice.incomingQueue = new PromiseQueue();
  MultiDevice.outgoingQueue = new PromiseQueue();

  // install our hook in order to discover the Noise keys
  window.crypto.subtle.importKey = async function (format, keyData, algorithm, extractable, keyUsages) {
    if (format == 'raw' && algorithm == 'AES-GCM' && keyData.length == 32 && extractable == false && keyUsages.length == 1) {
      var key = await originalImportKey.apply(window.crypto.subtle, [
        'raw',
        new Uint8Array(keyData),
        algorithm,
        false,
        ['decrypt', 'encrypt'],
      ]);

      if (keyUsages.includes('encrypt')) {
        MultiDevice.writeKey = keyData;
        MultiDevice.writeCounter = 0;
        MultiDevice.writeKeyImported = key;
        console.log('WAIncognito: Noise encryption key has been replaced.');
      } else if (keyUsages.includes('decrypt')) {
        MultiDevice.readKey = keyData;
        MultiDevice.readKeyImported = key;
        MultiDevice.readCounter = 0;
        console.log('WAIncognito: Noise decryption key has been replaced.');
      }
    }

    return originalImportKey.call(window.crypto.subtle, format, keyData, algorithm, extractable, keyUsages);
  };
};

MultiDevice.decryptNoisePacket = async function (payload, isIncoming = true) {
  if (MultiDevice.looksLikeHandshakePacket(payload) || MultiDevice.readKey == null) return null;

  // split to frames
  var binaryReader = new BinaryReader();
  binaryReader.writeBuffer(payload);
  binaryReader._readIndex = 0;

  var frames = [];
  while (binaryReader._readIndex + 3 < payload.byteLength) {
    var size = (binaryReader.readUint8() << 16) | binaryReader.readUint16();
    var frame = binaryReader.readBuffer(size);
    var counter = isIncoming ? MultiDevice.readCounter++ : MultiDevice.writeCounter++;
    var frameInfo = { frame: frame, counter: counter };

    frames.push(frameInfo);
  }

  try {
    for (var i = 0; i < frames.length; i++) {
      var frameInfo = frames[i];

      var currentFrame = frameInfo.frame;
      var counter = frameInfo.counter;

      var key = isIncoming ? MultiDevice.readKeyImported : MultiDevice.writeKeyImported;
      var algorithmInfo = { name: 'AES-GCM', iv: MultiDevice.counterToIV(counter), additionalData: new ArrayBuffer(0) };

      var decryptedFrame = await window.crypto.subtle.decrypt(algorithmInfo, key, currentFrame);
      var flags = new Uint8Array(decryptedFrame)[0];
      var decryptedFrameOpened = decryptedFrame.slice(1);
      if (flags & 2) {
        // zlib compressed. decompress
        decryptedFrameOpened = toArrayBuffer(pako.inflate(new Uint8Array(decryptedFrameOpened)));
      }

      frames[i] = { frame: decryptedFrameOpened, counter: counter, frameUncompressed: decryptedFrame };
    }
  } catch (exception) {
    if (exception.name.includes('OperationError')) {
      // reverse the counter, in case this is another socket
      if (isIncoming) MultiDevice.readCounter--;
      else MultiDevice.writeCounter--;

      throw 'Wrong counter in decryption';
    } else {
      console.error('Could not decrypt Noise packet');
      console.error(exception);
      debugger;
      throw exception;
    }
  }

  return frames;
};

MultiDevice.encryptAndPackNodesForSending = async function (nodesInfo, isIncoming = false) {
  // convert to binary protocol
  var packetBinaryWriter = new BinaryWriter();
  for (var i = 0; i < nodesInfo.length; i++) {
    var nodeInfo = nodesInfo[i];
    var node = nodeInfo.node;
    var counter = nodeInfo.counter;
    var decryptedFrame = nodeInfo.decryptedFrame;

    var nodeBuffer = await nodeReaderWriter.encodeStanza(node);

    // encrypt it
    var data = await MultiDevice.encryptPacket(nodeBuffer, isIncoming, counter);

    // Serialize to Noise protocol
    var binaryStream = new BinaryReader();

    var size = data.byteLength;
    binaryStream.writeUint8(size >> 16);
    binaryStream.writeUint16(65535 & size);
    binaryStream.write(data);

    binaryStream._readIndex = 0;
    var serializedPacket = binaryStream.readBuffer();

    packetBinaryWriter.pushBytes(serializedPacket);
  }

  return packetBinaryWriter.toBuffer();
};

MultiDevice.encryptPacket = async function (payload, isIncoming = true, counter = 0) {
  var keyData = isIncoming ? MultiDevice.readKey : MultiDevice.writeKey;
  var key = isIncoming ? MultiDevice.readKeyImported : MultiDevice.writeKeyImported;

  var algorithmInfo = { name: 'AES-GCM', iv: MultiDevice.counterToIV(counter), additionalData: new ArrayBuffer(0) };
  return window.crypto.subtle.encrypt(algorithmInfo, key, payload).catch(function (e) {
    console.error(e);
    //debugger;
  });
};

MultiDevice.sizeOfPacket = function (payload) {
  var binaryReader = new BinaryReader();
  binaryReader.writeBuffer(payload);
  binaryReader._readIndex = 0;

  var size = (binaryReader.readUint8() << 16) | binaryReader.readUint16();
  return size;
};

MultiDevice.enqueuePromise = async function (promise, argument, isIncoming = false) {
  var queue = isIncoming ? MultiDevice.incomingQueue : MultiDevice.outgoingQueue;
  return queue.enqueue(promise, argument);
};

MultiDevice.numPacketsSinceHandshake = 0;
MultiDevice.looksLikeHandshakePacket = function (payload) {
  // Noise protocol handshake flow:
  //    --> e                                                             [client hello]
  //    <-- e, s (encrypted), payload (encrypted NoiseCertificate)        [server hello]
  //    --> s (encrypted public key), payload (encrypted ClientPayload)   [client finish]
  // https://noiseprotocol.org/noise.html#handshake-patterns

  if (payload.byteLength < 8) {
    console.log('WAIncognito: got small packet:');
    console.log(payload);
    return true;
  }

  var binaryReader = new BinaryReader();
  binaryReader.writeBuffer(payload);

  var startOffset = 3;
  if (((binaryReader._readIndex = 0), binaryReader.readUint16() == 0x5741)) startOffset = 0x7; // chat
  if (((binaryReader._readIndex = 0xb), binaryReader.readUint16() == 0x5741)) startOffset = 0x12; // chat?ED={routingToken}

  if (startOffset > 3) MultiDevice.numPacketsSinceHandshake = 0; // client hello
  if (++MultiDevice.numPacketsSinceHandshake > 3) return false;

  var binary = payload.slice(startOffset, payload.length);
  try {
    var handshakeMessage = HandshakeMessage.read(new Pbf(binary));
  } catch {
    return false;
  }

  if (window.WAdebugMode) {
    if (handshakeMessage.clientHello) console.log('WAIncognito: client hello', handshakeMessage.clientHello);
    if (handshakeMessage.serverHello) console.log('WAIncognito: server hello', handshakeMessage.serverHello);
    if (handshakeMessage.clientFinish) console.log('WAIncognito: client finish', handshakeMessage.clientFinish);
  }

  return handshakeMessage.clientHello || handshakeMessage.serverHello || handshakeMessage.clientFinish;
};

MultiDevice.counterToIV = function (counter) {
  const buffer = new ArrayBuffer(12);
  new DataView(buffer).setUint32(8, counter);
  return new Uint8Array(buffer);
};

function toArrayBuffer(array) {
  return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset);
}

// https://medium.com/@karenmarkosyan/how-to-manage-promises-into-dynamic-queue-with-vanilla-javascript-9d0d1f8d4df5
class PromiseQueue {
  constructor() {
    this.queue = [];
    this.pendingPromise = false;
  }

  enqueue(promise, argument) {
    return new Promise((resolve, reject) => {
      this.queue.push({
        promise,
        argument,
        resolve,
        reject,
      });
      this.dequeue();
    });
  }

  dequeue() {
    if (this.workingOnPromise) {
      return false;
    }
    const item = this.queue.shift();
    if (!item) {
      return false;
    }
    try {
      this.workingOnPromise = true;
      item
        .promise(item.argument)
        .then(value => {
          this.workingOnPromise = false;
          item.resolve(value);
          this.dequeue();
        })
        .catch(err => {
          this.workingOnPromise = false;
          item.reject(err);
          this.dequeue();
        });
    } catch (err) {
      this.workingOnPromise = false;
      item.reject(err);
      this.dequeue();
    }
    return true;
  }
}

MultiDevice.initialize();
