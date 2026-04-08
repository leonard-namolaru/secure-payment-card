package secure.payment.card.client;

import javax.smartcardio.ResponseAPDU;

import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;

import secure.payment.card.client.HttpPayload.OperationResult;
import secure.payment.card.client.HttpPayload.SecurePaymentCardRecord;
import secure.payment.card.client.HttpPayload.HttpResponseBodyUnionType;

public abstract class SessionUserInterface implements UserInterface {
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
		
		sendMessageToUserIfVerbose("Vérification du code PIN de l'utilisateur");
		byte[] pin = this.getUserPin();
		if (!verifyUserPin(pin)) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
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
		if(!sendServerPublicKey()) {
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

		ResponseAPDU response = cardCommunicationChannel.verifyUserPin(pin);
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			sendMessageToUserIfVerbose(String.format("Échec de l'opération (SW:%04X)", response.getSW()));
			verifyPinResult = false;
		}
		
		return verifyPinResult;
	}
	
	private ECPublicKey getCardPublicKey() {
		ECPublicKey cardPublicKey = null;
		
		ResponseAPDU response = cardCommunicationChannel.getPublicKey();
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
	
	private boolean sendServerPublicKey() {
		boolean operationResult = true;
		
		ResponseAPDU response = cardCommunicationChannel.putPublicKey((ECPublicKey) clientKeyPair.getPublic());
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			sendMessageToUserIfVerbose(String.format("Échec de l'opération (SW:%04X)", response.getSW()));
			operationResult = false;					
		}
		
		return operationResult;
	}
	
	private byte[] getSecurePayementCardID() {
		byte[] securePayementCardID = null;
		
		ResponseAPDU response = cardCommunicationChannel.getSecurePayementCardID();
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
					ResponseAPDU response = cardCommunicationChannel.getBalance();
					if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
						operationResult = false;
						sendMessageToUser("Impossible d'obtenir le solde de la carte.");
					} else {
						byte[] balanceBytes = Crypto.getPlainTextAssociatedWithSignature(response, 2);
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
		ResponseAPDU response = cardCommunicationChannel.getBalance();
		sendMessageToUser(Util.convertResponseStatusCodeToString(response, false));
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			if (Crypto.verifyResponseApduSignature(cardSignatureObject, response, 2)) {
				sendMessageToUserIfVerbose("L'intégrité de la réponse a été vérifiée et confirmée.");
				byte[] balanceBytes = Crypto.getPlainTextAssociatedWithSignature(response, 2);
				sendMessageToUser("Solde : " + Util.bytesToShort(balanceBytes));
			} else {
				sendMessageToUser("Il semblerait que la réponse ait été modifiée pendant le transport.");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}
		}						

	}
	
	protected void debit(byte debitValue) {
		ResponseAPDU response = cardCommunicationChannel.debit(debitValue, antiReplayAttacksCounter ,clientSignatureObject);
		antiReplayAttacksCounter++; 
		sendMessageToUser(Util.convertResponseStatusCodeToString(response, false));
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			if (Crypto.verifyResponseApduSignature(cardSignatureObject, response, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2) ) {
				sendMessageToUserIfVerbose("L'intégrité de la réponse a été vérifiée et confirmée.");
				updateBalanceAfterDebit(debitValue);
			} else {
				sendMessageToUser("Il semblerait que la réponse ait été modifiée pendant le transport.");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}
		}
	}
	
	protected void credit(byte creditValue) {
		ResponseAPDU response = cardCommunicationChannel.credit(creditValue, antiReplayAttacksCounter ,clientSignatureObject);
		antiReplayAttacksCounter++; 
		sendMessageToUser(Util.convertResponseStatusCodeToString(response, false));
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			if (Crypto.verifyResponseApduSignature(cardSignatureObject, response, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2) ) {
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