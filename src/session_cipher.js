// vim: ts=4:sw=4:expandtab

const ChainType = require('./chain_type');
const ProtocolAddress = require('./protocol_address');
const SessionBuilder = require('./session_builder');
const SessionRecord = require('./session_record');
const crypto = require('./crypto');
const curve = require('./curve');
const errors = require('./errors');
const protobufs = require('./protobufs');
const queueJob = require('./queue_job');

const VERSION = 3;

function assertBuffer(value) {
    if (!(value instanceof Buffer)) {
        throw TypeError(`Expected Buffer instead of: ${value.constructor.name}`);
    }
    return value;
}

class SessionCipher {

    constructor(storage, protocolAddress) {
        if (!(protocolAddress instanceof ProtocolAddress)) {
            throw new TypeError("protocolAddress must be a ProtocolAddress");
        }
        this.addr = protocolAddress;
        this.storage = storage;
        this.builder = new SessionBuilder(storage, protocolAddress);
    }

    _encodeTupleByte(number1, number2) {
        if (number1 > 15 || number2 > 15) {
            throw TypeError("Numbers must be 4 bits or less");
        }
        return (number1 << 4) | number2;
    }

    _decodeTupleByte(byte) {
        return [byte >> 4, byte & 0xf];
    }

    toString() {
        return `<SessionCipher(${this.addr.toString()})>`;
    }

    async getRecord() {
        const record = await this.storage.loadSession(this.addr.toString());
        if (record && !(record instanceof SessionRecord)) {
            throw new TypeError('SessionRecord type expected from loadSession'); 
        }
        return record;
    }

    async getRecordOrCreate() {
        let record = await this.getRecord();
        if (!record) {
            record = new SessionRecord();
            await this.storeRecord(record);
        }
        return record;
    }

    async storeRecord(record) {
        if (record) {
            record.removeOldSessions();
            await this.storage.storeSession(this.addr.toString(), record);
        }
    }

    async queueJob(awaitable) {
        return await queueJob(this.addr.toString(), awaitable);
    }

    async encrypt(data) {
        assertBuffer(data);
        const ourIdentityKey = await this.storage.getOurIdentity();
        return await this.queueJob(async () => {
            let record = await this.getRecord();
            
            // Jika tidak ada record, coba buat session baru
            if (!record) {
                console.warn(`No session found for ${this.addr.toString()}, attempting to create one...`);
                record = new SessionRecord();
                await this.storeRecord(record);
                
                // Coba dapatkan PreKey bundle untuk membuat session
                try {
                    await this.attemptSessionCreation();
                    // Setelah mencoba membuat session, load ulang record
                    record = await this.getRecord();
                } catch (error) {
                    console.warn(`Failed to create session for ${this.addr.toString()}:`, error.message);
                    throw new errors.SessionError(`No session available for ${this.addr.id}. Please send a PreKey message first to establish session.`);
                }
            }
            
            if (!record) {
                throw new errors.SessionError(`No session record found for ${this.addr.toString()}`);
            }
            
            const session = record.getOpenSession();
            if (!session) {
                // Coba dapatkan session yang ada atau buat baru
                const sessions = record.getSessions();
                if (sessions && sessions.length > 0) {
                    // Gunakan session yang ada meskipun closed
                    console.warn(`Using closed session for ${this.addr.toString()}`);
                } else {
                    throw new errors.SessionError(`No open session available for ${this.addr.id}. Please establish a session first.`);
                }
            }
            
            const remoteIdentityKey = session.indexInfo.remoteIdentityKey;
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }
            
            const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey);
            if (!chain) {
                throw new errors.SessionError("No chain available for encryption");
            }
            
            if (chain.chainType === ChainType.RECEIVING) {
                throw new Error("Tried to encrypt on a receiving chain");
            }
            
            this.fillMessageKeys(chain, chain.chainKey.counter + 1);
            const keys = crypto.deriveSecrets(chain.messageKeys[chain.chainKey.counter],
                                              Buffer.alloc(32), Buffer.from("WhisperMessageKeys"));
            delete chain.messageKeys[chain.chainKey.counter];
            
            const msg = protobufs.WhisperMessage.create();
            msg.ephemeralKey = session.currentRatchet.ephemeralKeyPair.pubKey;
            msg.counter = chain.chainKey.counter;
            msg.previousCounter = session.currentRatchet.previousCounter;
            msg.ciphertext = crypto.encrypt(keys[0], data, keys[2].slice(0, 16));
            
            const msgBuf = protobufs.WhisperMessage.encode(msg).finish();
            const macInput = Buffer.alloc(msgBuf.byteLength + (33 * 2) + 1);
            macInput.set(ourIdentityKey.pubKey);
            macInput.set(session.indexInfo.remoteIdentityKey, 33);
            macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
            macInput.set(msgBuf, (33 * 2) + 1);
            
            const mac = crypto.calculateMAC(keys[1], macInput);
            const result = Buffer.alloc(msgBuf.byteLength + 9);
            result[0] = this._encodeTupleByte(VERSION, VERSION);
            result.set(msgBuf, 1);
            result.set(mac.slice(0, 8), msgBuf.byteLength + 1);
            
            await this.storeRecord(record);
            
            let type, body;
            if (session.pendingPreKey) {
                type = 3;  // prekey bundle
                const preKeyMsg = protobufs.PreKeyWhisperMessage.create({
                    identityKey: ourIdentityKey.pubKey,
                    registrationId: await this.storage.getOurRegistrationId(),
                    baseKey: session.pendingPreKey.baseKey,
                    signedPreKeyId: session.pendingPreKey.signedKeyId,
                    message: result
                });
                if (session.pendingPreKey.preKeyId) {
                    preKeyMsg.preKeyId = session.pendingPreKey.preKeyId;
                }
                body = Buffer.concat([
                    Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
                    Buffer.from(
                        protobufs.PreKeyWhisperMessage.encode(preKeyMsg).finish()
                    )
                ]);
            } else {
                type = 1;  // normal
                body = result;
            }
            
            return {
                type,
                body,
                registrationId: session.registrationId
            };
        });
    }

    // Metode baru: Mencoba membuat session
    async attemptSessionCreation() {
        try {
            // Coba dapatkan PreKey bundle dari storage
            const preKey = await this.storage.getNextPreKey();
            if (preKey) {
                const record = await this.getRecordOrCreate();
                await this.builder.initOutgoing(record, preKey);
                await this.storeRecord(record);
                return true;
            }
        } catch (error) {
            console.warn(`Session creation attempt failed for ${this.addr.toString()}:`, error.message);
        }
        return false;
    }

    async decryptWithSessions(data, sessions) {
        if (!sessions || !sessions.length) {
            throw new errors.SessionError("No sessions available");
        }   
        const errs = [];
        for (const session of sessions) {
            let plaintext; 
            try {
                plaintext = await this.doDecryptWhisperMessage(data, session);
                session.indexInfo.used = Date.now();
                return {
                    session,
                    plaintext
                };
            } catch(e) {
                errs.push(e);
            }
        }
        throw new errors.SessionError("No matching sessions found for message");
    }

    async decryptWhisperMessage(data) {
        assertBuffer(data);
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (!record) {
                throw new errors.SessionError("No session record found");
            }
            
            const sessions = record.getSessions();
            if (!sessions || !sessions.length) {
                throw new errors.SessionError("No sessions available for decryption");
            }
            
            const result = await this.decryptWithSessions(data, sessions);
            const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey;
            
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }   
            
            if (record.isClosed(result.session)) {
                console.warn("Decrypted message with closed session.");
            }
            
            await this.storeRecord(record);
            return result.plaintext;
        });
    }

    async decryptPreKeyWhisperMessage(data) {
        assertBuffer(data);
        const versions = this._decodeTupleByte(data[0]);
        if (versions[1] > 3 || versions[0] < 3) {
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }
        
        return await this.queueJob(async () => {
            let record = await this.getRecord();
            const preKeyProto = protobufs.PreKeyWhisperMessage.decode(data.slice(1));
            
            if (!record) {
                if (preKeyProto.registrationId == null) {
                    throw new Error("No registrationId provided in PreKey message");
                }
                record = new SessionRecord();
            }
            
            const preKeyId = await this.builder.initIncoming(record, preKeyProto);
            
            const session = record.getSession(preKeyProto.baseKey);
            if (!session) {
                throw new errors.SessionError("Failed to create session from PreKey message");
            }
            
            const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message, session);
            await this.storeRecord(record);
            
            if (preKeyId) {
                await this.storage.removePreKey(preKeyId);
            }
            
            return plaintext;
        });
    }

    async doDecryptWhisperMessage(messageBuffer, session) {
        assertBuffer(messageBuffer);
        if (!session) {
            throw new TypeError("session required");
        }
        
        const versions = this._decodeTupleByte(messageBuffer[0]);
        if (versions[1] > 3 || versions[0] < 3) {
            throw new Error("Incompatible version number on WhisperMessage");
        }
        
        const messageProto = messageBuffer.slice(1, -8);
        const message = protobufs.WhisperMessage.decode(messageProto);
        
        this.maybeStepRatchet(session, message.ephemeralKey, message.previousCounter);
        
        const chain = session.getChain(message.ephemeralKey);
        if (!chain) {
            throw new errors.SessionError("No chain found for ephemeral key");
        }
        
        if (chain.chainType === ChainType.SENDING) {
            throw new Error("Tried to decrypt on a sending chain");
        }
        
        this.fillMessageKeys(chain, message.counter);
        
        if (!chain.messageKeys.hasOwnProperty(message.counter)) {
            throw new errors.MessageCounterError('Key used already or never filled');
        }
        
        const messageKey = chain.messageKeys[message.counter];
        delete chain.messageKeys[message.counter];
        
        const keys = crypto.deriveSecrets(messageKey, Buffer.alloc(32),
                                          Buffer.from("WhisperMessageKeys"));
        
        const ourIdentityKey = await this.storage.getOurIdentity();
        const macInput = Buffer.alloc(messageProto.byteLength + (33 * 2) + 1);
        macInput.set(session.indexInfo.remoteIdentityKey);
        macInput.set(ourIdentityKey.pubKey, 33);
        macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
        macInput.set(messageProto, (33 * 2) + 1);
        
        crypto.verifyMAC(macInput, keys[1], messageBuffer.slice(-8), 8);
        
        const plaintext = crypto.decrypt(keys[0], message.ciphertext, keys[2].slice(0, 16));
        delete session.pendingPreKey;
        
        return plaintext;
    }

    fillMessageKeys(chain, counter) {
        if (chain.chainKey.counter >= counter) {
            return;
        }
        
        if (counter - chain.chainKey.counter > 2000) {
            throw new errors.SessionError('Over 2000 messages into the future!');
        }
        
        if (chain.chainKey.key === undefined) {
            throw new errors.SessionError('Chain closed');
        }
        
        const key = chain.chainKey.key;
        chain.messageKeys[chain.chainKey.counter + 1] = crypto.calculateMAC(key, Buffer.from([1]));
        chain.chainKey.key = crypto.calculateMAC(key, Buffer.from([2]));
        chain.chainKey.counter += 1;
        
        return this.fillMessageKeys(chain, counter);
    }

    maybeStepRatchet(session, remoteKey, previousCounter) {
        if (session.getChain(remoteKey)) {
            return;
        }
        
        const ratchet = session.currentRatchet;
        let previousRatchet = session.getChain(ratchet.lastRemoteEphemeralKey);
        
        if (previousRatchet) {
            this.fillMessageKeys(previousRatchet, previousCounter);
            delete previousRatchet.chainKey.key;
        }
        
        this.calculateRatchet(session, remoteKey, false);
        
        const prevCounter = session.getChain(ratchet.ephemeralKeyPair.pubKey);
        if (prevCounter) {
            ratchet.previousCounter = prevCounter.chainKey.counter;
            session.deleteChain(ratchet.ephemeralKeyPair.pubKey);
        }
        
        ratchet.ephemeralKeyPair = curve.generateKeyPair();
        this.calculateRatchet(session, remoteKey, true);
        ratchet.lastRemoteEphemeralKey = remoteKey;
    }

    calculateRatchet(session, remoteKey, sending) {
        let ratchet = session.currentRatchet;
        const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
        const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey,
                                               Buffer.from("WhisperRatchet"), 2);
        
        const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
        session.addChain(chainKey, {
            messageKeys: {},
            chainKey: {
                counter: -1,
                key: masterKey[1]
            },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING
        });
        
        ratchet.rootKey = masterKey[0];
    }

    async hasOpenSession() {
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (!record) {
                return false;
            }
            return record.haveOpenSession();
        });
    }

    async closeOpenSession() {
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (record) {
                const openSession = record.getOpenSession();
                if (openSession) {
                    record.closeSession(openSession);
                    await this.storeRecord(record);
                }
            }
        });
    }

    async getSessionInfo() {
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            return {
                hasRecord: !!record,
                sessionCount: record ? record.getSessions().length : 0,
                hasOpenSession: record ? record.haveOpenSession() : false,
                address: this.addr.toString()
            };
        });
    }

    // Metode untuk mengirim PreKey message untuk membangun session
    async sendPreKeyMessage() {
        return await this.queueJob(async () => {
            let record = await this.getRecordOrCreate();
            const preKey = await this.storage.getNextPreKey();
            
            if (!preKey) {
                throw new Error("No PreKeys available for session establishment");
            }
            
            await this.builder.initOutgoing(record, preKey);
            await this.storeRecord(record);
            
            // Sekarang encrypt pesan kosong untuk mendapatkan PreKey message
            const emptyMessage = Buffer.from([0]); // Pesan kosong
            return await this.encrypt(emptyMessage);
        });
    }
}

module.exports = SessionCipher;
