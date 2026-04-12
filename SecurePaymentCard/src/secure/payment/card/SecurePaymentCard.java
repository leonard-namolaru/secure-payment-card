package secure.payment.card;

import javacardx.crypto.Cipher;
import javacardx.security.cert.Certificate;
import javacardx.security.util.MonotonicCounter;

import javacard.framework.Util;

import org.globalplatform.Application;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.globalplatform.Personalization;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;

import javacard.security.AESKey;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.KeyAgreement;
import javacard.security.XECPublicKey;
import javacard.security.XECPrivateKey;
import javacard.security.MessageDigest;
import javacard.security.CryptoException;
import javacard.security.NamedParameterSpec;

public class SecurePaymentCard extends Applet /* implements Personalization, Application */ {
    private byte[] storedData = new byte[256];
    private short storedLength = 0;

	private short certificateOffset;
    private byte[] certificateBuffer;
	private Certificate clientCertificate;
	private byte[] authenticationChallenge;

	private AESKey aesKey;
	private Cipher aesCipherDecryptObject;
	private Cipher aesCipherEncryptObject;
	
    private short balance;
    private byte[] balanceSignature;
    private final OwnerPIN ownerPin;
    private byte[] securePayementCardID;
    private final KeyPair cardSigKeyPair;
    private final Signature cardSignature;
    private final Signature clientSignature;
    private final Signature cardSignatureCheck;
    private final XECPublicKey clientSigPublicKey;
    private final MonotonicCounter antiReplayAttacksCounter;

    private SecurePaymentCard(OwnerPIN ownerPin, MonotonicCounter antiReplayAttacksCounter, Signature cardSignature, Signature serverSignature, 
    		Signature cardSignatureCheck, KeyPair cardKeyPair, XECPublicKey serverPublicKey, short initialBalance, byte[] securePayementCardID, Certificate certificate) { 
    	this.certificateOffset = 0;
    	this.clientCertificate = certificate;
    	this.certificateBuffer = new byte[800];
    	this.authenticationChallenge = new byte[100];
    	
    	this.aesKey = null;
    	this.ownerPin = ownerPin;
    	this.balance = initialBalance;
    	this.cardSigKeyPair = cardKeyPair;
    	this.cardSignature = cardSignature;
    	this.clientSignature = serverSignature;
    	this.clientSigPublicKey = serverPublicKey;
    	this.cardSignatureCheck = cardSignatureCheck;
    	this.securePayementCardID = securePayementCardID;
    	this.antiReplayAttacksCounter = antiReplayAttacksCounter;
    	this.balanceSignature = new byte[SecurePaymentCardConstants.SIGNATURE_SIZE];
    	    	
    	this.genKeyPair();
    	signBalance();
    }
    
    public static void install(byte[] installParameters, short offset, byte length) {
        short appletDataLengthOffset = handleInstallParameters(installParameters, offset, length);
        byte appletDataLength  = (byte) (installParameters[appletDataLengthOffset] 
        		& SecurePaymentCardConstants.PARAMETER_DATA_MAXIMUM_SIZE);  
        
        NamedParameterSpec namedParameterSpec = NamedParameterSpec.getInstance(NamedParameterSpec.SECP256R1); // secp256r1 curve
        
        XECPrivateKey cardPrivateKey = (XECPrivateKey) KeyBuilder.buildXECKey(
        		namedParameterSpec, (short) (KeyBuilder.ATTR_PRIVATE | JCSystem.MEMORY_TYPE_TRANSIENT_RESET), false);
        XECPublicKey cardPublicKey = (XECPublicKey) KeyBuilder.buildXECKey(namedParameterSpec, 
        		(short) (KeyBuilder.ATTR_PUBLIC | JCSystem.MEMORY_TYPE_PERSISTENT), false);
        XECPublicKey clientPublicKey = (XECPublicKey) KeyBuilder.buildXECKey(namedParameterSpec, 
        		(short) (KeyBuilder.ATTR_PUBLIC | JCSystem.MEMORY_TYPE_TRANSIENT_RESET), false);
        
        Signature cardSignature = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        Signature serverSignature = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        Signature cardSignatureCheck = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);

        KeyPair keyPair = new KeyPair(cardPublicKey, cardPrivateKey);
        OwnerPIN pin = new OwnerPIN(SecurePaymentCardConstants.PIN_MAX_INCORRECT_TRIES, SecurePaymentCardConstants.PIN_SIZE);
        MonotonicCounter counter = MonotonicCounter.getInstance(SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        
        if ((appletDataLength - SecurePaymentCardConstants.CARD_ID_LENGTH) < SecurePaymentCardConstants.PIN_SIZE) {
        	ISOException.throwIt((short) (SecurePaymentCardConstants.SW_PIN_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_PIN_TOO_SMALL));
        }
        pin.update(installParameters, (short) (appletDataLengthOffset + 1 + SecurePaymentCardConstants.CARD_ID_LENGTH), SecurePaymentCardConstants.PIN_SIZE);

        byte[] securePayementCardID = new byte[SecurePaymentCardConstants.CARD_ID_LENGTH];
  
        // arrayCopy​(byte[] src, short srcOff, byte[] dest, short destOff, short length)
        Util.arrayCopy(installParameters, (short) (appletDataLengthOffset + 1), securePayementCardID, (short) 0, (short) SecurePaymentCardConstants.CARD_ID_LENGTH);
        
        // GPSystem.getRegistryEntry(JCSystem.getAID()).setState(GPSystem.SECURITY_DOMAIN_PERSONALIZED);
        
        SecurePaymentCard securePaymentCard = new SecurePaymentCard(pin, counter, cardSignature, serverSignature, 
    			cardSignatureCheck, keyPair, clientPublicKey, (short) 0, securePayementCardID, null);
    	securePaymentCard.register();
    }
    
    // JCRE 11.2.1
    // Les paramètres d'installation sont encodés au format (L,V).
    public static short handleInstallParameters(byte[] installParameters, short offset, byte length) {        
        byte instanceAidLength = (byte) (installParameters[offset] & SecurePaymentCardConstants.PARAMETER_DATA_MAXIMUM_SIZE);            
       
        offset += (short) (instanceAidLength + 1);
        byte controlInfoLength = (byte) (installParameters[offset] & SecurePaymentCardConstants.PARAMETER_DATA_MAXIMUM_SIZE);  
       
        offset += (short) (controlInfoLength + 1);
        byte appletDataLength  = (byte) (installParameters[offset] & SecurePaymentCardConstants.PARAMETER_DATA_MAXIMUM_SIZE);  
  
        // Pour vérifier si les paramètres d'installation contiennent des valeurs "illégales"
        if ((short)(instanceAidLength + controlInfoLength + appletDataLength + 3) > length) {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }
        
        return offset;
    }
    
    @Override
    public boolean select() {
        try {
        	cardSignatureCheck.init(cardSigKeyPair.getPublic(), Signature.MODE_VERIFY);
        } catch(CryptoException e) {
            ISOException.throwIt(SecurePaymentCardConstants.SW_KEY_GENERATION_FAILED);
        }
    	
        if (!verifyBalance()) {
            ISOException.throwIt((short) 0x009);
        }
    	
    	byte pinTriesRemaining = ownerPin.getTriesRemaining();
    	boolean selectable = true;
    	
    	// L'applet ne peut pas être sélectionnée si le code PIN est bloqué.
    	// Cela signifie que l'applet doit être supprimée puis réinstallée.    	
    	if (pinTriesRemaining == 0) {
    		selectable = false;
    	}
    	this.certificateOffset = 0;

    	this.genKeyPair();
    	signBalance();
        return selectable;
    }
    
    void signBalance() {
    	byte[] buffer = new byte[2];
    	Util.setShort(buffer, (short) 0, this.balance);
    	this.sign(buffer, this.balanceSignature);
    }
    
    boolean verifyBalance() {
    	byte[] buffer = new byte[2];
    	Util.setShort(buffer, (short) 0, balance);
    	return verifySignature(cardSignatureCheck, buffer, balanceSignature);
    }

    @Override
    public void deselect() {
        ownerPin.reset();
    }
    
    @Override
    public void process(APDU incomingApduCommand) {
    	
        try {
        	// L'objet APDU contient un tableau d'octets (tampon) pour transférer les commandes et les réponses APDU 
        	// entrantes et sortantes entre l'application cliente et l'applet.

        	// Si la commande APDU est SELECT
        	boolean isSelectApduCommand = this.selectingApplet();
        	if (isSelectApduCommand) {        	
        		return;
        	}
        
        	// À ce stade, seuls les premiers octets d'en-tête [CLA, INS, P1, P2, Nc] sont disponibles dans le tampon APDU.
        	byte[] apduBufferByteArray = incomingApduCommand.getBuffer();
        
        	byte claByte = apduBufferByteArray[ISO7816.OFFSET_CLA];
        	byte insByte = apduBufferByteArray[ISO7816.OFFSET_INS];
        	if (claByte != SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD) {
        		ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        	}
        
        	if (insByte == SecurePaymentCardConstants.INS_GET_BALANCE 
        			|| insByte == SecurePaymentCardConstants.INS_DEBIT 
        			|| insByte == SecurePaymentCardConstants.INS_CREDIT) {
        		if (!ownerPin.isValidated()) {
        			PINException.throwIt(SecurePaymentCardConstants.SW_PIN_VERIFICATION_REQUIRED);
        		}
        	}
        
        	if (!verifyBalance()) {
        		ISOException.throwIt((short) 0x009);
        	}
        
        	switch (insByte) {
            	case SecurePaymentCardConstants.INS_GET_BALANCE:
            		getBalance(incomingApduCommand, apduBufferByteArray);
            		break;
            	case SecurePaymentCardConstants.INS_DEBIT:
            		debit(incomingApduCommand, apduBufferByteArray);
            		break;
            	case SecurePaymentCardConstants.INS_CREDIT:
            		credit(incomingApduCommand, apduBufferByteArray);
            		break;
            	case SecurePaymentCardConstants.INS_VERIFY_PIN:
            		verifyPin(incomingApduCommand);
            		break;
            	case SecurePaymentCardConstants.INS_GET_SIG_PUBLIC_KEY:
            		sendCardPublicKey(incomingApduCommand);
            		break; 
            	case SecurePaymentCardConstants.INS_PUT_SIG_PUBLIC_KEY:
            		getClientPublicKey(incomingApduCommand);
            		break; 
            	case SecurePaymentCardConstants.INS_GET_PAYEMENT_CARD_ID:
            		sendSecurePayementCardID(incomingApduCommand);
            		break; 
            	case SecurePaymentCardConstants.INS_CLIENT_CARD_KEY_AGREEMENT:
            		keyAgreement(incomingApduCommand);
            		break; 
            	case SecurePaymentCardConstants.INS_SEND_CLIENT_CERTIFICATE:
            		getClientCertificate(incomingApduCommand);
            		break; 
            	case SecurePaymentCardConstants.INS_CHALLENGE_RESPONSE:
            		clientAuthentication(incomingApduCommand);
            		break;
            	default:
            		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        	}
        } catch (ISOException exception) {
            throw exception; 
        } catch (PINException exception) {
            ISOException.throwIt((short) (SecurePaymentCardConstants.SW_PIN_EXCEPTION_PREFIX | exception.getReason()));
        } catch (CryptoException exception) {
            ISOException.throwIt((short) (SecurePaymentCardConstants.SW_CRYPTO_EXCEPTION_PREFIX | exception.getReason()));
        } catch (TransactionException exception) {
            ISOException.throwIt((short) (SecurePaymentCardConstants.SW_TRANSACTION_EXCEPTION_PREFIX | exception.getReason()));
        }
     }
    
    private void clientAuthentication(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
        short byteRead = apdu.setIncomingAndReceive();
        
        Signature sig = Signature.getInstance(MessageDigest.ALG_SHA, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1, false);
        sig.init(clientCertificate.getPublicKey(), Signature.MODE_VERIFY);
        
        byte[] signatureBuffer = new byte[256];
        signatureBuffer[0] = buffer[ISO7816.OFFSET_P2];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, signatureBuffer, (short) 1, byteRead);
        
        if (!verifySignature(sig, authenticationChallenge, signatureBuffer)) {
        	ISOException.throwIt((short) 0x06);
        }
    }
    
    private void getClientCertificate(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
        short byteRead = apdu.setIncomingAndReceive();
        boolean isLastMessage = buffer[ISO7816.OFFSET_P1] == 0x01;

        // arrayCopy​(byte[] src, short srcOff, byte[] dest, short destOff, short length)
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, certificateBuffer, this.certificateOffset, byteRead);
        
        if (isLastMessage) {
            Cert cert = new Cert();
            this.clientCertificate = cert.buildCert(certificateBuffer, (short) 0, (short) (this.certificateOffset + byteRead));
            
            RandomData.OneShot rng = RandomData.OneShot.open(RandomData.ALG_TRNG);
            rng.nextBytes(authenticationChallenge, (short) 0, (short) authenticationChallenge.length);
            
            // arrayCopy​(byte[] src, short srcOff, byte[] dest, short destOff, short length)
            Util.arrayCopy(authenticationChallenge, (short) 0, buffer, (short) 0, (short) authenticationChallenge.length);
            apdu.setOutgoingAndSend((short) 0, (short) authenticationChallenge.length);
       }
        
        this.certificateOffset += 120;
    }
    
    private void keyAgreement(APDU apdu) { 
        NamedParameterSpec namedParameterSpec = NamedParameterSpec.getInstance(NamedParameterSpec.SECP256R1); // secp256r1 curve
        XECPrivateKey cardPrivateKey = (XECPrivateKey) KeyBuilder.buildXECKey(
        		namedParameterSpec, (short) (KeyBuilder.ATTR_PRIVATE | JCSystem.MEMORY_TYPE_TRANSIENT_RESET), false);
        XECPublicKey cardPublicKey = (XECPublicKey) KeyBuilder.buildXECKey(namedParameterSpec, 
        		(short) (KeyBuilder.ATTR_PUBLIC | JCSystem.MEMORY_TYPE_TRANSIENT_RESET), false);
        XECPublicKey clientPublicKey = (XECPublicKey) KeyBuilder.buildXECKey(namedParameterSpec, 
        		(short) (KeyBuilder.ATTR_PUBLIC | JCSystem.MEMORY_TYPE_TRANSIENT_RESET), false);

        KeyPair keyPair = new KeyPair(cardPublicKey, cardPrivateKey);
        keyPair.genKeyPair();
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        keyAgreement.init(keyPair.getPrivate());
        
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        clientPublicKey.setEncoded(buffer, ISO7816.OFFSET_CDATA, byteRead);
        
        byte[] secret = new byte[32];
        byte[] publicKeyBytes = new byte[clientPublicKey.getEncodingLength()];
        short publicKeyBytesLength = clientPublicKey.getEncoded(publicKeyBytes, (short) 0);
        
        // short generateSecret​(byte[] publicData, short publicOffset, short publicLength, byte[] secret, short secretOffset)
        keyAgreement.generateSecret(publicKeyBytes, (short) 0, (short) publicKeyBytesLength, secret, (short)0);

		this.aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
		this.aesKey.setKey(secret,(short) 16);
		
		this.aesCipherEncryptObject = Cipher.getInstance(Cipher.ALG_AES_ECB_PKCS5, false);
		this.aesCipherEncryptObject.init(this.aesKey, Cipher.MODE_ENCRYPT);
		
		this.aesCipherDecryptObject = Cipher.getInstance(Cipher.ALG_AES_ECB_PKCS5, false);
		this.aesCipherDecryptObject.init(this.aesKey, Cipher.MODE_DECRYPT);

        short copiedDataOffsetAndLength = cardPublicKey.getEncoded(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, copiedDataOffsetAndLength);
    }
    
    private byte[] handleIncomingApduData(APDU incomingApduCommand, byte[] apduBufferByteArray, short dataLength, boolean withSignature) { 
    	byte clientCounterSize = 1;
    	
    	byte[] expectedCounterValue = new byte[SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE];
    	antiReplayAttacksCounter.get(expectedCounterValue, (short) 0);
        antiReplayAttacksCounter.incrementBy((short) 1);

    	// L'octet Lc désigne le nombre d'octets dans le champ data de la commande APDU  
        byte numBytes = apduBufferByteArray[ISO7816.OFFSET_LC];

        // Indique que cette APDU a des données à partir de ISO7816.OFFSET_CDATA ,suivant les 5 octets d'en-tête.
        byte byteRead = (byte) (incomingApduCommand.setIncomingAndReceive());
        
        // Si le nombre d'octets de données lus ne correspond pas au nombre d'octets dans Lc.
        if (numBytes != byteRead) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        byte[] decryptedBuffer = new byte[byteRead];
    	// short doFinal​(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
    	short outputLength = aesCipherDecryptObject.doFinal(apduBufferByteArray, ISO7816.OFFSET_CDATA, byteRead, decryptedBuffer, (short) 0);
    	
        byte[] data = new byte[dataLength];
        // arrayCopy​(byte[] src, short srcOff, byte[] dest, short destOff, short length)
        Util.arrayCopy(decryptedBuffer, (short) 0, data, (short) 0, dataLength);

        byte clientCounterValue = decryptedBuffer[dataLength];
        if (clientCounterValue != expectedCounterValue[SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE - 1]) {
            ISOException.throwIt((short) (outputLength - 1));
        }

        if (withSignature && !verifySignature(decryptedBuffer, (short) 0, (short) (dataLength + clientCounterSize), (short) (outputLength - dataLength - clientCounterSize))) {
            ISOException.throwIt((short) 2);
        }
    	return data;
    }

    private void credit(APDU incomingApduCommand, byte[] apduBufferByteArray) {
    	byte creditAmount = handleIncomingApduData(incomingApduCommand, apduBufferByteArray, (short) 1, true)[0];
        if (((creditAmount & 0xFF) > SecurePaymentCardConstants.MAX_TRANSACTION) || (creditAmount < 0)) {
            TransactionException.throwIt(SecurePaymentCardConstants.SW_INVALID_TRANSACTION);
        }

        if ((short) (balance + creditAmount) > SecurePaymentCardConstants.MAX_BALANCE) {
        	TransactionException.throwIt(SecurePaymentCardConstants.SW_MAXIMUM_BALANCE);
        }

        JCSystem.beginTransaction();
        balance = (short) (balance + creditAmount);
   	 	signBalance();
        JCSystem.commitTransaction();
        
        short offset = Util.setShort(apduBufferByteArray, (short) 0, creditAmount);
        offset = generateResponseBuffer(offset, apduBufferByteArray, true);
        incomingApduCommand.setOutgoingAndSend((short) 0, offset);
    }
    
    private void debit(APDU incomingApduCommand, byte[] apduBufferByteArray) {
        byte debitAmount = handleIncomingApduData(incomingApduCommand, apduBufferByteArray, (short) 1, true)[0];
                
        if (((debitAmount & 0xFF) > SecurePaymentCardConstants.MAX_TRANSACTION) || (debitAmount < 0)) {
        	TransactionException.throwIt(SecurePaymentCardConstants.SW_INVALID_TRANSACTION);
        }

        if ((short) (balance - debitAmount) < (short) 0) {
        	TransactionException.throwIt(SecurePaymentCardConstants.SW_NEGATIVE_BALANCE);
        }
        
        JCSystem.beginTransaction();
        balance = (short) (balance - debitAmount);
   	 	signBalance();
        JCSystem.commitTransaction();
        
        short offset = Util.setShort(apduBufferByteArray, (short) 0, debitAmount);
        offset = generateResponseBuffer(offset, apduBufferByteArray, true);
        incomingApduCommand.setOutgoingAndSend((short) 0, offset);
    }

    private void getBalance(APDU incomingApduCommand, byte[] apduBufferByteArray) {
    	handleIncomingApduData(incomingApduCommand, apduBufferByteArray, (short) 0, true);
    	
        short offset = Util.setShort(apduBufferByteArray, (short) 0, balance);
        offset = generateResponseBuffer(offset, apduBufferByteArray, true);
        incomingApduCommand.setOutgoingAndSend((short) 0, offset);
    }
    
    private void verifyPin(APDU incomingApduCommand) {
        byte[] buffer = incomingApduCommand.getBuffer();
        byte[] pin = handleIncomingApduData(incomingApduCommand, buffer, SecurePaymentCardConstants.PIN_SIZE, true);
                
        if (ownerPin.check(pin, (short) 0, (byte) pin.length) == false) {
            PINException.throwIt(SecurePaymentCardConstants.SW_PIN_VERIFICATION_FAILED);
        }
    }
    
    private void getClientPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte[] encodedPublicKey = handleIncomingApduData(apdu, buffer, (short) 65, false);

        try {
        	// void setEncoded​(byte[] value, short offset, short length)
            clientSigPublicKey.setEncoded(encodedPublicKey, (short) 0, (short) encodedPublicKey.length);
            clientSignature.init(clientSigPublicKey, Signature.MODE_VERIFY);
        } catch (CryptoException e) {
            CryptoException.throwIt(SecurePaymentCardConstants.SW_SIGNATURE_INITIALIZATION_FAILED);
        }
    }
    
    private void sendSecurePayementCardID(APDU apdu) {   
    	handleIncomingApduData(apdu, apdu.getBuffer(), (short) 0, true);
    	
        // arrayCopy​(byte[] src, short srcOff, byte[] dest, short destOff, short length)
        short copiedDataOffsetAndLength = Util.arrayCopy(securePayementCardID, (short) 0, apdu.getBuffer(), (short) 0, (short) securePayementCardID.length);
        apdu.setOutgoingAndSend((short) 0, copiedDataOffsetAndLength);
    }
    
    private void sendCardPublicKey(APDU apdu) {
    	handleIncomingApduData(apdu, apdu.getBuffer(), (short) 0, false);

        try {
            XECPublicKey publicKey = (XECPublicKey) cardSigKeyPair.getPublic();
            short copiedDataOffsetAndLength = publicKey.getEncoded(apdu.getBuffer(), (short) 0);
            apdu.setOutgoingAndSend((short) 0, copiedDataOffsetAndLength);
        } catch(Exception e) {
            ISOException.throwIt(SecurePaymentCardConstants.SW_KEY_GENERATION_FAILED);
        }
    }

    private short generateResponseBuffer(short offset, byte[] output, boolean includeCounter) {
        short position = offset;
        try {            
            if (includeCounter) {
                position = antiReplayAttacksCounter.get(output, position);
            }
            
            // Une vue en lecture seule sur les données d'entrée à signer
            byte[] signInputData = JCSystem.makeByteArrayView(output, (short) 0, (short) position, JCSystem.ATTR_READABLE_VIEW, null);
            // Une vue en écriture seule sur la mémoire tampon de sortie où la signature doit être stockée
            byte[] signBuffer = JCSystem.makeByteArrayView(output, position, (short) (output.length - position), JCSystem.ATTR_WRITABLE_VIEW, null);            
            
            // Ajout de la signature
            position += sign(signInputData, signBuffer);
            
            byte[] tmp = new byte[position];
            // short arrayCopy(byte[] src, short srcOff, byte[] dest, short destOff, short length)
            Util.arrayCopy(output, (short) 0, tmp, (short) 0, position);
            
        	// short doFinal​(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
        	short outputLength = aesCipherEncryptObject.doFinal(tmp, (short) 0, (short) tmp.length, output, (short) 0);
        	return outputLength;
        } catch (ArithmeticException | CryptoException | SystemException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        return position;
    }
    
    
	/* *******************************************************************************************
	 ************************************** CRYPTOGRAPHIE ****************************************    
	 ******************************************************************************************* */        
    
    private void genKeyPair() {
    	try {
            cardSigKeyPair.genKeyPair();
    	} catch(CryptoException e) {
            CryptoException.throwIt(SecurePaymentCardConstants.SW_KEY_GENERATION_FAILED);
        }
    	
        try {
            cardSignature.init(cardSigKeyPair.getPrivate(), Signature.MODE_SIGN);
        	cardSignatureCheck.init(cardSigKeyPair.getPublic(), Signature.MODE_VERIFY);
        } catch(CryptoException e) {
            CryptoException.throwIt(SecurePaymentCardConstants.SW_SIGNATURE_INITIALIZATION_FAILED);
        }
    }
    
    private short sign(byte[] input, byte[] output) {
    	// sign​(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) 
        return cardSignature.sign(input, (short) 0, (short) input.length, output, (short) 0);
    }    
    
    private boolean verifySignature(Signature signatureObject, byte[] message, byte[] signature) {
    	// verify​(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength)
    	return signatureObject.verify(message, (short) 0, (short) message.length, signature, (short) 0, (short) signature.length);
    }
    
    private boolean verifySignature(byte[] input, short messageOffset, short messageLength, short signatureLength) {
    	// verify​(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength)
    	return clientSignature.verify(input, messageOffset, messageLength, input, (short) (messageOffset + messageLength), signatureLength);
    }
    
    //@Override
	public short processData(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        short dataOffset = (short) (inOffset + 5);
        short dataLength = (short) (inBuffer[(short) (inOffset + 4)] & 0xFF);
        Util.arrayCopy(inBuffer, dataOffset, storedData, (short) 0, dataLength);
        storedLength = dataLength;
        return 0;
	}
    
    //@Override
	public void processData(byte[] baBuffer, short sOffset, short sLength) {
        short dataOffset = (short) (sOffset + 5);
        short dataLength = (short) (baBuffer[(short) (sOffset + 4)] & 0xFF);
        Util.arrayCopy(baBuffer, dataOffset, storedData, (short) 0, dataLength);
        storedLength = dataLength;		
	}
}