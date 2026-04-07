package secure.payment.card.client;

import java.security.KeyPair;
import java.security.Signature;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.ResponseAPDU;

import secure.payment.card.client.HttpPayload.AuthenticationResponse;
import secure.payment.card.client.HttpPayload.HttpResponseBodyUnionType;
import secure.payment.card.client.HttpPayload.OperationResult;
import secure.payment.card.client.HttpPayload.SecurePaymentCardRecord;

public abstract class SessionUserInterface implements UserInterface {
    private short balance;
    private byte[] balanceSignature;
    protected String securePayementCardID;
    protected byte antiReplayAttacksCounter;
    
	protected boolean debug;
	protected boolean verbose;
	private KeyPair serverKeyPair;
	private ECPublicKey cardPublicKey;
	protected Signature cardSignatureObject;
	protected Signature serverSignatureObject;
	protected CardCommunicationChannel cardCommunicationChannel;
	protected ServerCommunicationChannel serverCommunicationChannel;
	
	public SessionUserInterface(CardCommunicationChannel cardCommunicationChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug, boolean verbose) {
		this.debug = debug;
		this.verbose = verbose;
		this.antiReplayAttacksCounter = 0;
		this.cardCommunicationChannel = cardCommunicationChannel;
		this.serverCommunicationChannel = serverCommunicationChannel;
		
		this.cardSignatureObject = Crypto.setSignatureAlgorithm();
		this.serverSignatureObject = Crypto.setSignatureAlgorithm();
		if (cardSignatureObject == null || serverSignatureObject == null) {
			sendMessageToUser("Crypto.setSignatureAlgorithm() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Select applet");
		if (!selectApplet()) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Verify user pin");
		byte[] pin = this.getUserPin();
		if (!verifyUserPin(pin)) {
			sendMessageToUser("getUserPin() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Get card public key");
		this.cardPublicKey = getCardPublicKey();
		if (cardPublicKey == null) {
			sendMessageToUser("getCardPublicKey() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.serverKeyPair = generateServerKeyPair();
		
		sendMessageToUserIfDebug("Send server public key");
		if(!sendServerPublicKey()) {
			sendMessageToUser("sendServerPublicKey() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		if(!Crypto.signatureInitVerify(cardSignatureObject, cardPublicKey)) {
			sendMessageToUser("cardSignatureInitVerify() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		if(!Crypto.signatureInitSign(serverSignatureObject, (ECPrivateKey) serverKeyPair.getPrivate())) {
			sendMessageToUser("serverSignatureInitSign() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Get secure payement card ID");
		byte[] securePayementCardIdBytes = getSecurePayementCardID();
		if(securePayementCardIdBytes == null) {
			System.out.println("getSecurePayementCardID() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.securePayementCardID = new String(securePayementCardIdBytes);
		sendMessageToUser(String.format("\nID : %s\n", securePayementCardID));
		
		if (!setAndVerifyInitialBalance()) {
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	}
	
	private boolean selectApplet() {
		boolean selectResult = true;
		
		ResponseAPDU response = cardCommunicationChannel.selectApplet();
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			selectResult = false;
		}
		
		return selectResult;
	}
	
	private boolean verifyUserPin(byte[] pin) {
		boolean verifyPinResult = true;

		ResponseAPDU response = cardCommunicationChannel.verifyUserPin(pin);
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			verifyPinResult = false;
		}
		
		return verifyPinResult;
	}
	
	private ECPublicKey getCardPublicKey() {
		ECPublicKey cardPublicKey = null;
		
		ResponseAPDU response = cardCommunicationChannel.getPublicKey();
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
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
		
		ResponseAPDU response = cardCommunicationChannel.putPublicKey((ECPublicKey) serverKeyPair.getPublic());
		if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
			operationResult = false;					
		}
		
		return operationResult;
	}
	
	private byte[] getSecurePayementCardID() {
		byte[] securePayementCardID = null;
		
		ResponseAPDU response = cardCommunicationChannel.getSecurePayementCardID();
		if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
			securePayementCardID = response.getData();				
		} 
		return securePayementCardID;
	}
	
	private SecurePaymentCardRecord getSecurePayementCardDataFromServer() {
		sendMessageToUserIfVerbose("Obtention de la signature du dernier solde, "
				+ "ainsi que de la clé publique, auprès du serveur ...");
		
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
		
		byte[] publicKey = Crypto.getByteArrayFromPublicKey((ECPublicKey) serverKeyPair.getPublic());
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
		this.balanceSignature = Crypto.signMessage(serverSignatureObject, balanceBytes);
	}
	
	protected boolean updateBalanceAfterDebit(byte debitAmount) {
		balance = (short) (balance - debitAmount);
		signBalance();
		return updateSecurePayementCardData();
	}

	protected boolean updateBalanceAfterCredit(byte creditAmount) {
		balance = (short) (balance + creditAmount);
		signBalance();
		return updateSecurePayementCardData();
	}

	protected abstract void run();
	protected abstract byte[] getUserPin();
	public abstract void sendMessageToUser(String message);
	public abstract void sendMessageToUserIfDebug(String message);
	public abstract void sendMessageToUserIfVerbose(String message);
}
