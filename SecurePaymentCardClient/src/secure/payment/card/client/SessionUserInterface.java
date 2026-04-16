package secure.payment.card.client;

import java.util.ArrayList;
import java.io.ByteArrayInputStream;

import javax.crypto.Cipher;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.security.Key;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import secure.payment.card.client.JsonPayload.OperationResult;
import secure.payment.card.client.JsonPayload.SecurePaymentCardRecord;
import secure.payment.card.client.JsonPayload.HttpResponseBodyUnionType;

public abstract class SessionUserInterface implements UserInterface {
	private Key aesKey;
	private Cipher aesCipherDecryptObject;
	private Cipher aesCipherEncryptObject;
	
	KeyPair rsaKeyPair;
	Signature rsaSignatureSign;
	Signature rsaSignatureVerify;
	X509Certificate cardCertificate;
	
	protected boolean debug;
	protected boolean verbose;

    private short balance;
    private byte[] balanceSignature;
    private String securePayementCardID;
    private byte antiReplayAttacksCounter;
    
	private KeyPair clientKeyPair;
	private ECPublicKey cardPublicKey;
	private Signature cardSignatureObject;
	private Signature clientSignatureObject;
	private CardCommunicationChannel cardCommunicationChannel;
	private ServerCommunicationChannel serverCommunicationChannel;
	
	public SessionUserInterface(CardCommunicationChannel cardCommunicationChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug, boolean verbose) {
		this.debug = debug;
		this.verbose = verbose;
		this.antiReplayAttacksCounter = 0;
		this.cardCommunicationChannel = cardCommunicationChannel;
		this.serverCommunicationChannel = serverCommunicationChannel;
		
		this.cardSignatureObject = Crypto.setSignatureAlgorithm();
		this.clientSignatureObject = Crypto.setSignatureAlgorithm();
		if (cardSignatureObject == null || clientSignatureObject == null) {
			sendMessageToUser("Échec de l'initialisation de l'algorithme de signature.");
			throw new RuntimeException();	
		}
		
		sendMessageToUserIfVerbose("Envoi de la commande SELECT à la carte");
		if (!selectApplet()) {
			sendMessageToUser("Échec de la commande SELECT.");
			throw new RuntimeException();	
		}
		
		sendMessageToUserIfVerbose("Echange de certificats");
		this.rsaKeyPair = Crypto.generateRsaKeyPair();
		this.cardCertificate = sendAndGetCertificate();
		if (this.cardCertificate != null) {
			sendMessageToUser("L'échange de certificats a été effectué avec succès.");
		} else {
			sendMessageToUser("L'échange de certificats a échoué.");
			throw new RuntimeException();	
		}
		
		sendMessageToUserIfVerbose("Authentification du client et de la carte");
		if (sendAndGetChallenge()) {
			sendMessageToUser("L'authentification a réussi.");
		} else {
			sendMessageToUser("L'authentification a échoué.");
			throw new RuntimeException();	
		}
		
		sendMessageToUserIfVerbose("Génération d'une clé partagée");
		this.aesKey = generateSharedKey();
		if(this.aesKey == null) {
			sendMessageToUser("Échec de la génération de la clé partagée.");
			throw new RuntimeException();		
		}
		
		this.aesCipherDecryptObject = Crypto.initCipherObject(Cipher.DECRYPT_MODE, aesKey);
		if(this.aesCipherDecryptObject == null) {
			sendMessageToUser("Échec de l'initialisation du mécanisme de déchiffrement.");
			sendMessageToUserIfDebug("Échec de l'initialisation de l'objet Cipher avec l'état Cipher.DECRYPT_MODE");
			throw new RuntimeException();		
		}
		
		this.aesCipherEncryptObject = Crypto.initCipherObject(Cipher.ENCRYPT_MODE, aesKey);
		if(this.aesCipherEncryptObject == null) {
			sendMessageToUser("Échec de l'initialisation du mécanisme de chiffrement.");
			sendMessageToUserIfDebug("Échec de l'initialisation de l'objet Cipher avec l'état Cipher.ENCRYPT_MODE");
			throw new RuntimeException();		
		}
		
		sendMessageToUserIfVerbose("Obtention de la clé publique de la carte (pour les signatures)");
		this.cardPublicKey = getCardPublicKey();
		if (cardPublicKey == null) {
			sendMessageToUser("Impossible d'obtenir la clé publique de la carte.");
			throw new RuntimeException();		
		}
		
		this.clientKeyPair = generateServerKeyPair();
		
		sendMessageToUserIfVerbose("Envoi de la clé publique du client (pour les signatures)");
		if(!sendClientPublicKey()) {
			sendMessageToUser("Impossible d'envoyer la clé publique du client à la carte.");
			throw new RuntimeException();		
		}
		
		if(!Crypto.signatureInitVerify(cardSignatureObject, cardPublicKey)) {
			sendMessageToUser("Le mécanisme de vérification des signatures de la carte n'a pas pu être initialisé.");
			throw new RuntimeException();		
		}

		if(!Crypto.signatureInitSign(clientSignatureObject, (ECPrivateKey) clientKeyPair.getPrivate())) {
			sendMessageToUser("Le mécanisme de génération des signatures du client n'a pas pu être initialisé.");
			throw new RuntimeException();		
		}
		
		sendMessageToUserIfVerbose("Vérification du code PIN de l'utilisateur");
		byte[] pin = this.getUserPin();
		if (!verifyUserPin(pin)) {
			sendMessageToUser("Échec de la vérification du code PIN.");
			throw new RuntimeException();		
		}
		
		sendMessageToUserIfVerbose("Obtention de l'ID de la carte");
		byte[] securePayementCardIdBytes = getSecurePayementCardID();
		if(securePayementCardIdBytes == null) {
			sendMessageToUser("Il n'a pas été possible d'obtenir l'ID de la carte.");
			throw new RuntimeException();		
		}
		
		sendMessageToUserIfVerbose("\n");
		this.securePayementCardID = new String(securePayementCardIdBytes);
		sendMessageToUser(String.format("ID : %s\n", securePayementCardID));
		
		if (!setAndVerifyInitialBalance()) {
			throw new RuntimeException();		
		}
		
		sendMessageToUser("Solde : " + balance);
		sendMessageToUser("La session a démarré");
	}
	
	private X509Certificate sendAndGetCertificate() {		
		X509Certificate clientCertificate = Crypto.createSelfSignedCertificate(this.rsaKeyPair);		
		ResponseAPDU response = cardCommunicationChannel.sendCertificate(SecurePaymentCardConstants.INS_SEND_CERTIFICATE, clientCertificate);
		sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			ByteArrayInputStream inputStream = new ByteArrayInputStream(response.getData());
			
			CertificateFactory certFactory = null;
			try {
				certFactory = CertificateFactory.getInstance("X.509");
			} catch (CertificateException e) {
				return null;
			}
			try {
				return (X509Certificate) certFactory.generateCertificate(inputStream);
			} catch (CertificateException e) {
				return null;
			}
		} 
		
		return null;
	}
	
	private boolean sendAndGetChallenge() {
		boolean authenticationResult = true;
		
	      SecureRandom random = new SecureRandom();
	      byte cardChallenge[] = new byte[50];
	      random.nextBytes(cardChallenge);

		ResponseAPDU response = cardCommunicationChannel.sendAndGetChallenge(cardChallenge);
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			byte[] challenge = response.getData();

			try {
				rsaSignatureSign = Signature.getInstance("SHA1withRSA", "BC");
				rsaSignatureSign.initSign(rsaKeyPair.getPrivate());
				rsaSignatureSign.update(challenge);

				byte[] signature = rsaSignatureSign.sign();
				response = cardCommunicationChannel.sendChallengeResponse(signature);
				if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
					authenticationResult = false;
				} else {
					rsaSignatureVerify = Signature.getInstance("SHA1withRSA", "BC");
					rsaSignatureVerify.initVerify(cardCertificate);
					rsaSignatureVerify.update(cardChallenge);
					
					return rsaSignatureVerify.verify(response.getData());
				}
			} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
				sendMessageToUserIfDebug(String.format("%s : %s", e.getClass().toString(), e.getMessage()));
				authenticationResult = false;
			}
		} else {
			authenticationResult = false;
		}
		
		return authenticationResult;

	}
	
	private Key generateSharedKey() {
		antiReplayAttacksCounter++;
		
		int i = 0;
		KeyPair keyPair = null;
		byte[] encodedPublicKey = null;
		while (encodedPublicKey == null && i < 5) {
			keyPair = Crypto.generateKeyPair();
			encodedPublicKey = Crypto.getByteArrayFromPublicKey((ECPublicKey) keyPair.getPublic(), this);	
			i++;
		}
				
		byte[] encodedPublicKeyWithCounter = new byte[encodedPublicKey.length + 1];
		System.arraycopy(encodedPublicKey, 0, encodedPublicKeyWithCounter, 0, encodedPublicKey.length);
		encodedPublicKeyWithCounter[encodedPublicKey.length] = antiReplayAttacksCounter;
		
		byte[] signature = null;
		try {
			rsaSignatureSign.update(encodedPublicKeyWithCounter);
			signature = rsaSignatureSign.sign();
		} catch (SignatureException e) {
			return null;
		}
		
		byte[] payload = Util.concatArrays(encodedPublicKeyWithCounter, signature);
		ArrayList<CommandAPDU> commands = cardCommunicationChannel.splitPayload(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_CLIENT_CARD_KEY_AGREEMENT, payload, (byte) 0x00);
		ResponseAPDU response = cardCommunicationChannel.sendCommands(commands);
		sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			int cardCounter = Util.bytesToInt(response.getData(), 65, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE);
			
			byte[] message = new byte[65 + SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE];
			System.arraycopy(response.getData(), 0, message, 0, message.length);
			
			byte[] messageSignature = new byte[response.getData().length - (65 + SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE)];
			System.arraycopy(response.getData(), 65 + SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE, messageSignature, 0, messageSignature.length);

			try {
				rsaSignatureVerify.initVerify(cardCertificate);
				rsaSignatureVerify.update(message);
				if (!rsaSignatureVerify.verify(messageSignature)) {
					return null;
				}
			} catch (SignatureException | InvalidKeyException e) {
				return null;
			}
			
			byte[] cardPublicKeyByteArray = new byte[65];
			System.arraycopy(response.getData(), 0, cardPublicKeyByteArray, 0, 65);
			ECPublicKey cardPublicKey = Crypto.getPublicKeyFromByteArray(cardPublicKeyByteArray);		
			
			byte[] sharedSecret = Crypto.generateSharedSecret(cardPublicKey, keyPair.getPrivate());
			if (sharedSecret != null) {
			    return Crypto.createAesKey(sharedSecret, 16, 16);
			}
		} else {
			sendMessageToUserIfVerbose("Il n'est pas possible de générer une clé partagée.");
		}
		
		return null;
	}
	
	private boolean selectApplet() {
		boolean selectResult = true;
		
		ResponseAPDU response = cardCommunicationChannel.selectApplet();
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			sendMessageToUserIfVerbose(String.format("Échec de l'opération (SW:%04X)", response.getSW()));
			selectResult = false;
		}
		
		return selectResult;
	}
	
	private boolean verifyUserPin(byte[] pin) {
		boolean verifyPinResult = true;
		ResponseAPDU response = cardCommunicationChannel.verifyUserPin(pin, antiReplayAttacksCounter ,clientSignatureObject, aesCipherEncryptObject);
		
		antiReplayAttacksCounter++;
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			sendMessageToUserIfVerbose(String.format("Échec de l'opération (SW:%04X)", response.getSW()));
			verifyPinResult = false;
		} else {
			sendMessageToUserIfVerbose("Le code PIN est correct.");
		}
		
		return verifyPinResult;
	}
	
	private ECPublicKey getCardPublicKey() {
		ECPublicKey cardPublicKey = null;
		ResponseAPDU response = cardCommunicationChannel.getPublicKey(antiReplayAttacksCounter, aesCipherEncryptObject);
		
		antiReplayAttacksCounter++; 
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			sendMessageToUserIfVerbose(String.format("Échec de l'opération (SW:%04X)", response.getSW()));
			cardPublicKey = null;				
		} else {
			byte[] cardPublicKeyByteArray = response.getData();
			cardPublicKey = Crypto.getPublicKeyFromByteArray(cardPublicKeyByteArray);		
		}
		
		return cardPublicKey;
	}
	
	private KeyPair generateServerKeyPair() {
		return Crypto.generateKeyPair();
	}
	
	private boolean sendClientPublicKey() {
		boolean operationResult = true;
		ResponseAPDU response = cardCommunicationChannel.putPublicKey((ECPublicKey) clientKeyPair.getPublic(), antiReplayAttacksCounter, aesCipherEncryptObject);
		
		antiReplayAttacksCounter++; 
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			sendMessageToUserIfVerbose(String.format("Échec de l'opération (SW:%04X)", response.getSW()));
			operationResult = false;					
		}
		
		return operationResult;
	}
	
	private byte[] getSecurePayementCardID() {
		byte[] securePayementCardID = null;
		ResponseAPDU response = cardCommunicationChannel.getSecurePayementCardID(antiReplayAttacksCounter ,clientSignatureObject, aesCipherEncryptObject);
		
		antiReplayAttacksCounter++; 
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			securePayementCardID = response.getData();				
		} else {
			sendMessageToUserIfVerbose(String.format("Échec de l'opération (SW:%04X)", response.getSW()));
		}
		return securePayementCardID;
	}
	
	private SecurePaymentCardRecord getSecurePayementCardDataFromServer() {
		sendMessageToUserIfVerbose("Obtention de la signature du dernier solde, "
				+ "ainsi que la clé publique, auprès du serveur");
		
		HttpResponseBodyUnionType<SecurePaymentCardRecord> httpResponse = 
				serverCommunicationChannel.getSecurePaymentCardRecord(securePayementCardID);
		if (!httpResponse.isError()) {
			return httpResponse.getExpectedResponseBody();
		} else {
			sendMessageToUserIfVerbose("L'opération a échoué.");
			sendMessageToUser(httpResponse.getErrorResponse().toString());
			return null;
		}
	}
	
	private boolean updateSecurePayementCardData() {
		sendMessageToUserIfVerbose("Mise à jour de la signature du solde, "
				+ "ainsi que de la clé publique, auprès du serveur");
		
		byte[] publicKey = Crypto.getByteArrayFromPublicKey((ECPublicKey) clientKeyPair.getPublic(), this);
		if (publicKey == null) {
			return false;
		}
		
		HttpResponseBodyUnionType<OperationResult> httpResponse = 
				serverCommunicationChannel.updateSecurePaymentCardRecord(securePayementCardID, publicKey, balanceSignature);
		if (!httpResponse.isError()) {
			return httpResponse.getExpectedResponseBody().isOk();
		} else {
			sendMessageToUserIfVerbose("L'opération a échoué.");
			sendMessageToUser(httpResponse.getErrorResponse().toString());
			return false;
		}
	}
	
	private boolean setAndVerifyInitialBalance() {
		boolean operationResult = true;

		SecurePaymentCardRecord securePaymentCardRecord = getSecurePayementCardDataFromServer();
		if (securePaymentCardRecord == null) {
			operationResult = false;
			sendMessageToUser("Le contrôle d'intégrité du solde de la carte n'a pas pu être effectué.");
		} else {
			this.balanceSignature = Util.hexToBytes(securePaymentCardRecord.balanceSignature);
			ECPublicKey publicKey = Crypto.getPublicKeyFromByteArray(Util.hexToBytes(securePaymentCardRecord.publicKey));
			
			Signature signatureObject = Crypto.setSignatureAlgorithm();
			if (signatureObject == null) {
				operationResult = false;
				sendMessageToUser("Le contrôle d'intégrité du solde de la carte n'a pas pu être effectué.");
			} else {
				if (!Crypto.signatureInitVerify(signatureObject, publicKey)) {
					operationResult = false;
					sendMessageToUser("Le contrôle d'intégrité du solde de la carte n'a pas pu être effectué.");
				} else {
					ResponseAPDU response = cardCommunicationChannel.getBalance(antiReplayAttacksCounter ,clientSignatureObject, aesCipherEncryptObject);
					
					antiReplayAttacksCounter++;
					if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
						operationResult = false;
						sendMessageToUser("Impossible d'obtenir le solde de la carte.");
					} else {
						byte[] decryptedValue = Crypto.decryptAes(aesCipherDecryptObject, response.getData());
						if (decryptedValue == null) {
							sendMessageToUser("Le message ne peut pas être déchiffré.");
							operationResult = false;
						} else {
							sendMessageToUserIfDebug(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));
							byte[] balanceBytes = Crypto.getPlainTextAssociatedWithSignature(decryptedValue, 2);
							this.balance = Util.bytesToShort(balanceBytes);
							if (!Crypto.verifySignature(signatureObject, balanceBytes, balanceSignature)) {
								operationResult = false;
								sendMessageToUser("Problème d'intégrité concernant le solde de la carte.");
							} else {
								sendMessageToUserIfVerbose("La vérification de l'intégrité du montant stocké "
										+ "sur la carte a été effectuée avec succès.");
							}
						}
					}
				}
			}
		}

		return operationResult;
	}
	
	private void signBalance() {
		byte[] balanceBytes = Util.shortToBytes(balance);
		this.balanceSignature = Crypto.signMessage(clientSignatureObject, balanceBytes);
	}
	
	private boolean updateBalanceAfterDebit(byte debitAmount) {
		balance = (short) (balance - debitAmount);
		signBalance();
		return updateSecurePayementCardData();
	}

	private boolean updateBalanceAfterCredit(byte creditAmount) {
		balance = (short) (balance + creditAmount);
		signBalance();
		return updateSecurePayementCardData();
	}
	
	protected void getBalance() {
		ResponseAPDU response = cardCommunicationChannel.getBalance(antiReplayAttacksCounter ,clientSignatureObject, aesCipherEncryptObject);
		sendMessageToUser(Util.convertResponseStatusCodeToString(response, false));
		
		antiReplayAttacksCounter++;
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			byte[] decryptedValue = Crypto.decryptAes(aesCipherDecryptObject, response.getData());
			if (decryptedValue == null) {
				sendMessageToUser("Le message ne peut pas être déchiffré.");
				return;
			}
			sendMessageToUserIfDebug(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));

			if (Crypto.verifyResponseApduSignature(cardSignatureObject, decryptedValue, 6)) {
				int cardCounter = Util.bytesToInt(decryptedValue, 2, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE);

				sendMessageToUserIfVerbose("L'intégrité de la réponse a été vérifiée et confirmée.");
				byte[] balanceBytes = Crypto.getPlainTextAssociatedWithSignature(decryptedValue, 2);
				sendMessageToUser("Solde : " + Util.bytesToShort(balanceBytes));
			} else {
				sendMessageToUser("Il semblerait que la réponse ait été modifiée pendant le transport.");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}
		}						

	}
	
	protected void debit(byte debitValue) {
		ResponseAPDU response = cardCommunicationChannel.debit(debitValue, antiReplayAttacksCounter ,clientSignatureObject, aesCipherEncryptObject);
		antiReplayAttacksCounter++; 
		sendMessageToUser(Util.convertResponseStatusCodeToString(response, false));
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			byte[] decryptedValue = Crypto.decryptAes(aesCipherDecryptObject, response.getData());
			if (decryptedValue == null) {
				sendMessageToUser("Le message ne peut pas être déchiffré.");
				return;
			}
			sendMessageToUserIfDebug(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));

			if (Crypto.verifyResponseApduSignature(cardSignatureObject, decryptedValue, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2) ) {
				sendMessageToUserIfVerbose("L'intégrité de la réponse a été vérifiée et confirmée.");
				updateBalanceAfterDebit(debitValue);
				sendMessageToUserIfVerbose("Solde : " + balance);
			} else {
				sendMessageToUser("Il semblerait que la réponse ait été modifiée pendant le transport.");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}
		}
	}
	
	protected void credit(byte creditValue) {
		ResponseAPDU response = cardCommunicationChannel.credit(creditValue, antiReplayAttacksCounter ,clientSignatureObject, aesCipherEncryptObject);
		antiReplayAttacksCounter++; 
		sendMessageToUser(Util.convertResponseStatusCodeToString(response, false));
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			byte[] decryptedValue = Crypto.decryptAes(aesCipherDecryptObject, response.getData());
			if (decryptedValue == null) {
				sendMessageToUser("Le message ne peut pas être déchiffré.");
				return;
			}
			sendMessageToUserIfDebug(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));
			if (Crypto.verifyResponseApduSignature(cardSignatureObject, decryptedValue, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2) ) {
				updateBalanceAfterCredit(creditValue);
				sendMessageToUserIfVerbose("Solde : " + balance);
			} else {
				sendMessageToUser("Il semblerait que la réponse ait été modifiée pendant le transport.");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}
		}
	}

	protected abstract void run();
	protected abstract byte[] getUserPin();
	public abstract void sendMessageToUser(String message);
	public abstract void sendMessageToUserIfDebug(String message);
	public abstract void sendMessageToUserIfVerbose(String message);
}