package secure.payment.card;

import javacard.framework.Util;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;

import javacard.security.KeyPair;
import javacard.security.Signature;
import javacard.security.KeyBuilder;
import javacard.security.XECPublicKey;
import javacard.security.XECPrivateKey;
import javacard.security.MessageDigest;
import javacard.security.CryptoException;
import javacard.security.NamedParameterSpec;

import javacardx.crypto.Cipher;
import javacardx.security.util.MonotonicCounter;

public class SecurePaymentCard extends Applet {
    private short balance;
    private byte[] balanceSignature;
    private final OwnerPIN ownerPin;
    private final KeyPair cardKeyPair;
    private byte[] securePayementCardID;
    private final Signature cardSignature;
    private final Signature serverSignature;
    private final Signature cardSignatureCheck;
    private final XECPublicKey serverPublicKey;
    private final MonotonicCounter antiReplayAttacksCounter;

    private SecurePaymentCard(OwnerPIN ownerPin, MonotonicCounter antiReplayAttacksCounter, Signature cardSignature, Signature serverSignature, 
    		Signature cardSignatureCheck, KeyPair cardKeyPair, XECPublicKey serverPublicKey, short initialBalance, byte[] securePayementCardID) { 
    	this.ownerPin = ownerPin;
    	this.balance = initialBalance;
    	this.cardKeyPair = cardKeyPair;
    	this.cardSignature = cardSignature;
    	this.serverSignature = serverSignature;
    	this.serverPublicKey = serverPublicKey;
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
        XECPublicKey serverPublicKey = (XECPublicKey) KeyBuilder.buildXECKey(namedParameterSpec, 
        		(short) (KeyBuilder.ATTR_PUBLIC | JCSystem.MEMORY_TYPE_TRANSIENT_RESET), false);
        
        Signature cardSignature = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        Signature serverSignature = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        Signature cardSignatureCheck = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);

        KeyPair keyPair = new KeyPair(cardPublicKey, cardPrivateKey);
        OwnerPIN pin = new OwnerPIN(SecurePaymentCardConstants.PIN_MAX_INCORRECT_TRIES, SecurePaymentCardConstants.PIN_SIZE);
        MonotonicCounter counter = MonotonicCounter.getInstance(SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        
        if (appletDataLength < SecurePaymentCardConstants.PIN_SIZE) {
        	ISOException.throwIt((short) (SecurePaymentCardConstants.SW_PIN_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_PIN_TOO_SMALL));
        }
                
        pin.update(installParameters, (short) (appletDataLengthOffset + 1), SecurePaymentCardConstants.PIN_SIZE);
    	
        byte securePayementCardIdLength = (byte) (appletDataLength - SecurePaymentCardConstants.PIN_SIZE);
        byte[] securePayementCardID = new byte[securePayementCardIdLength];
        
        // arrayCopy​(byte[] src, short srcOff, byte[] dest, short destOff, short length)
        Util.arrayCopy(installParameters, (short) (appletDataLengthOffset + 1 + SecurePaymentCardConstants.PIN_SIZE), securePayementCardID, (short) 0, (short) securePayementCardIdLength);
        
        SecurePaymentCard securePaymentCard = new SecurePaymentCard(pin, counter, cardSignature, serverSignature, 
    			cardSignatureCheck, keyPair, serverPublicKey, (short) 0, securePayementCardID);
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
        	cardSignatureCheck.init(cardKeyPair.getPublic(), Signature.MODE_VERIFY);
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
        
        	if (insByte != SecurePaymentCardConstants.INS_VERIFY_PIN) {
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
            	case SecurePaymentCardConstants.INS_GET_PUBLIC_KEY:
            		sendCardPublicKey(incomingApduCommand);
            		break; 
            	case SecurePaymentCardConstants.INS_PUT_PUBLIC_KEY:
            		getServerPublicKey(incomingApduCommand);
            		break; 
            	case SecurePaymentCardConstants.INS_GET_PAYEMENT_CARD_ID:
            		sendSecurePayementCardID(incomingApduCommand);
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
        
    private void credit(APDU incomingApduCommand, byte[] apduBufferByteArray) {
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

        byte creditAmount = apduBufferByteArray[ISO7816.OFFSET_CDATA];
        byte clientCounterValue = apduBufferByteArray[ISO7816.OFFSET_CDATA + 1];
        
        if (clientCounterValue != expectedCounterValue[SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE - 1]) {
            ISOException.throwIt((short) 1);
        }

        if (!verifySignature(apduBufferByteArray, (short) 2, (short) (byteRead - 2))) {
            ISOException.throwIt((short) 2);
        }
    	
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

        short offset = generateResponseBuffer(creditAmount, apduBufferByteArray, (short) 0, true);
        incomingApduCommand.setOutgoingAndSend((short) 0, offset);
    }
    
    private void debit(APDU incomingApduCommand, byte[] apduBufferByteArray) {
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
        
        byte debitAmount = apduBufferByteArray[ISO7816.OFFSET_CDATA];
        byte clientCounterValue = apduBufferByteArray[ISO7816.OFFSET_CDATA + 1];
        
        if (clientCounterValue != expectedCounterValue[SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE - 1]) {
            ISOException.throwIt((short) expectedCounterValue[SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE - 1]);
        }
        
        if (!verifySignature(apduBufferByteArray, (short) 2, (short) (byteRead - 2))) {
            ISOException.throwIt((short) byteRead);
        }
        
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

        short offset = generateResponseBuffer(debitAmount, apduBufferByteArray, (short) 0, true);
        incomingApduCommand.setOutgoingAndSend((short) 0, offset);
    }

    private void getBalance(APDU incomingApduCommand, byte[] apduBufferByteArray) {
        short offset = generateResponseBuffer(balance, apduBufferByteArray, (short) 0, false);
        incomingApduCommand.setOutgoingAndSend((short) 0, offset);
    }
    
    private void verifyPin(APDU incomingApduCommand) {
        byte[] buffer = incomingApduCommand.getBuffer();
        byte byteRead = (byte) (incomingApduCommand.setIncomingAndReceive());
        
        if (byteRead < SecurePaymentCardConstants.PIN_SIZE) {
            PINException.throwIt(SecurePaymentCardConstants.SW_PIN_TOO_SMALL);
        }
        
        if (ownerPin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            PINException.throwIt(SecurePaymentCardConstants.SW_PIN_VERIFICATION_FAILED);
        }
    }
    
    
    private void getServerPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        
        try {
        	// void setEncoded​(byte[] value, short offset, short length)
            serverPublicKey.setEncoded(buffer, ISO7816.OFFSET_CDATA, byteRead);
            serverSignature.init(serverPublicKey, Signature.MODE_VERIFY);
        } catch (CryptoException e) {
            CryptoException.throwIt(SecurePaymentCardConstants.SW_SIGNATURE_INITIALIZATION_FAILED);
        }
    }
    
    private void sendSecurePayementCardID(APDU apdu) {        
        // arrayCopy​(byte[] src, short srcOff, byte[] dest, short destOff, short length)
        short copiedDataOffsetAndLength = Util.arrayCopy(securePayementCardID, (short) 0, apdu.getBuffer(), (short) 0, (short) securePayementCardID.length);
        apdu.setOutgoingAndSend((short) 0, copiedDataOffsetAndLength);
    }

    private void sendCardPublicKey(APDU apdu) {
        try {
            XECPublicKey publicKey = (XECPublicKey) cardKeyPair.getPublic();
            short copiedDataOffsetAndLength = publicKey.getEncoded(apdu.getBuffer(), (short) 0);
            apdu.setOutgoingAndSend((short) 0, copiedDataOffsetAndLength);
        } catch(Exception e) {
            ISOException.throwIt(SecurePaymentCardConstants.SW_KEY_GENERATION_FAILED);
        }
    }

    private short generateResponseBuffer(short value, byte[] output, short offset, boolean includeCounter) {
        short position = offset;
        try {
            // Ecrire la valeur ( + compteur si includeCounter == true)
            position = Util.setShort(output, position, value);
            
            if (includeCounter) {
                position = antiReplayAttacksCounter.get(output, position);
            }
            
            // Une vue en lecture seule sur les données d'entrée à signer
            byte[] signInputData = JCSystem.makeByteArrayView(output, offset, (short) (position - offset), JCSystem.ATTR_READABLE_VIEW, null);
            // Une vue en écriture seule sur la mémoire tampon de sortie où la signature doit être stockée
            byte[] signBuffer = JCSystem.makeByteArrayView(output, position, (short) (output.length - position), JCSystem.ATTR_WRITABLE_VIEW, null);

            // Ajout de la signature
            position += sign(signInputData, signBuffer);
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
            cardKeyPair.genKeyPair();
    	}  catch(CryptoException e) {
            CryptoException.throwIt(SecurePaymentCardConstants.SW_KEY_GENERATION_FAILED);
        }
    	
        try {
            cardSignature.init(cardKeyPair.getPrivate(), Signature.MODE_SIGN);
        	cardSignatureCheck.init(cardKeyPair.getPublic(), Signature.MODE_VERIFY);
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

    private boolean verifySignature(byte[] input, short messageLength, short signatureLength) {
    	// verify​(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength)
    	return serverSignature.verify(input, ISO7816.OFFSET_CDATA, messageLength, input, (short) (ISO7816.OFFSET_CDATA + messageLength), signatureLength);
    }
}