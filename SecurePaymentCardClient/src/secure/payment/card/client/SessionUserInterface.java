package secure.payment.card.client;

import javax.crypto.Cipher;
import javax.smartcardio.ResponseAPDU;

import java.security.Key;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import secure.payment.card.client.HttpPayload.OperationResult;
import secure.payment.card.client.HttpPayload.SecurePaymentCardRecord;
import secure.payment.card.client.HttpPayload.HttpResponseBodyUnionType;

public abstract class SessionUserInterface implements UserInterface {
	private Key aesKey;
	private Cipher aesCipherDecryptObject;
	private Cipher aesCipherEncryptObject;

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
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfVerbose("Envoi de la commande SELECT à la carte");
		if (!selectApplet()) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfVerbose("Authentification du client");
		if (clientAuthentication()) {
			sendMessageToUser("L'authentification du client a réussi.");
		} else {
			sendMessageToUser("L'authentification du client a échoué.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfVerbose("Génération d'une clé partagée");
		this.aesKey = generateSharedKey();
		if(this.aesKey == null) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.aesCipherDecryptObject = Crypto.initCipherObject(Cipher.DECRYPT_MODE, aesKey);
		if(this.aesCipherDecryptObject == null) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug("Échec de l'initialisation de l'objet Cipher avec l'état Cipher.DECRYPT_MODE");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.aesCipherEncryptObject = Crypto.initCipherObject(Cipher.ENCRYPT_MODE, aesKey);
		if(this.aesCipherEncryptObject == null) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug("Échec de l'initialisation de l'objet Cipher avec l'état Cipher.ENCRYPT_MODE");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfVerbose("Obtention de la clé publique de la carte");
		this.cardPublicKey = getCardPublicKey();
		if (cardPublicKey == null) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.clientKeyPair = generateServerKeyPair();
		
		sendMessageToUserIfVerbose("Envoi de la clé publique du client");
		if(!sendClientPublicKey()) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		if(!Crypto.signatureInitVerify(cardSignatureObject, cardPublicKey)) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		if(!Crypto.signatureInitSign(clientSignatureObject, (ECPrivateKey) clientKeyPair.getPrivate())) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfVerbose("Vérification du code PIN de l'utilisateur");
		byte[] pin = this.getUserPin();
		if (!verifyUserPin(pin)) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfVerbose("Obtention de l'ID de la carte");
		byte[] securePayementCardIdBytes = getSecurePayementCardID();
		if(securePayementCardIdBytes == null) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfVerbose("\n");
		this.securePayementCardID = new String(securePayementCardIdBytes);
		sendMessageToUser(String.format("ID : %s\n", securePayementCardID));
		
		if (!setAndVerifyInitialBalance()) {
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	}
	
	private boolean clientAuthentication() {
		boolean authenticationResult = true;
		
		KeyPair keyPair = Crypto.generateRsaKeyPair();
		X509Certificate certificate = Crypto.createSelfSignedCertificate(keyPair);		
		ResponseAPDU response = cardCommunicationChannel.sendClientCertificate(certificate);
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			byte[] challenge = response.getData();
			
			try {
				Signature signatureObject = Signature.getInstance("SHA1withRSA", "BC");
				signatureObject.initSign(keyPair.getPrivate());
				signatureObject.update(challenge);
				
				byte[] signature = signatureObject.sign();
				response = cardCommunicationChannel.sendChallengeResponse(signature);
				if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
					authenticationResult = false;
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
		KeyPair keyPair = Crypto.generateKeyPair();
		ResponseAPDU response = cardCommunicationChannel.keyAgreement((ECPublicKey) keyPair.getPublic());
		
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			byte[] cardPublicKeyByteArray = response.getData();
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
				+ "ainsi que la clé publique, auprès du serveur ...");
		
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
				+ "ainsi que de la clé publique, auprès du serveur ...");
		
		byte[] publicKey = Crypto.getByteArrayFromPublicKey((ECPublicKey) clientKeyPair.getPublic());
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
							sendMessageToUserIfVerbose(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));
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
			sendMessageToUserIfVerbose(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));

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
			sendMessageToUserIfVerbose(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));

			if (Crypto.verifyResponseApduSignature(cardSignatureObject, decryptedValue, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2) ) {
				sendMessageToUserIfVerbose("L'intégrité de la réponse a été vérifiée et confirmée.");
				updateBalanceAfterDebit(debitValue);
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
			sendMessageToUserIfVerbose(String.format("\t\t     [APDU-R-DECRYPTED] [%s]", Util.convertByteArrayToString(decryptedValue)));
			if (Crypto.verifyResponseApduSignature(cardSignatureObject, decryptedValue, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2) ) {
				updateBalanceAfterCredit(creditValue);
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