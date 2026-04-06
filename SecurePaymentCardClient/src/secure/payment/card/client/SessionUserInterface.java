package secure.payment.card.client;

import java.security.KeyPair;
import java.security.Signature;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.ResponseAPDU;

public abstract class SessionUserInterface implements UserInterface {
    private short balance;
    private byte[] balanceSignature;
    protected String securePayementCardID;
    protected byte antiReplayAttacksCounter;
    
	protected boolean debug;
	private KeyPair serverKeyPair;
	private ECPublicKey cardPublicKey;
	protected Signature cardSignatureObject;
	protected Signature serverSignatureObject;
	protected CardCommunicationChannel cardCommunicationChannel;
	protected ServerCommunicationChannel serverCommunicationChannel;
	
	public SessionUserInterface(CardCommunicationChannel cardCommunicationChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug) {
		this.debug = debug;
		this.antiReplayAttacksCounter = 0;
		this.cardCommunicationChannel = cardCommunicationChannel;
		this.serverCommunicationChannel = serverCommunicationChannel;
		
		this.cardSignatureObject = Crypto.setSignatureAlgorithm();
		this.serverSignatureObject = Crypto.setSignatureAlgorithm();
		if (cardSignatureObject == null || serverSignatureObject == null) {
			System.out.println("Signature.getInstance : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Select applet");
		if (!selectApplet()) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Verify user pin");
		byte[] pin = this.getUserPin();
		if (!verifyUserPin(pin)) {
			System.out.println("getUserPin() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Get card public key");
		this.cardPublicKey = getCardPublicKey();
		if (cardPublicKey == null) {
			System.out.println("getCardPublicKey() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.serverKeyPair = generateServerKeyPair();
		
		sendMessageToUserIfDebug("Send server public key");
		if(!sendServerPublicKey()) {
			System.out.println("sendServerPublicKey() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		if(!Crypto.cardSignatureInitVerify(cardSignatureObject, cardPublicKey)) {
			System.out.println("cardSignatureInitVerify() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		if(!Crypto.serverSignatureInitSign(serverSignatureObject, (ECPrivateKey) serverKeyPair.getPrivate())) {
			System.out.println("serverSignatureInitSign() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		sendMessageToUserIfDebug("Get secure payement card ID");
		byte[] securePayementCardIdBytes = getSecurePayementCardID();
		if(securePayementCardIdBytes == null) {
			System.out.println("getSecurePayementCardID() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.securePayementCardID = new String(securePayementCardIdBytes);
		sendMessageToUser(String.format("\nID : %s", securePayementCardID));
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

	protected abstract void run();
	protected abstract byte[] getUserPin();
	public abstract void sendMessageToUser(String message);
	public abstract void sendMessageToUserIfDebug(String message);
}
