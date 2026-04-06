package secure.payment.card.client;

import java.util.List;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CardException;

import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.AMSession;
import com.oracle.javacard.ams.config.AID;

/**
 * Communication avec la carte
 */
public class CardCommunicationChannel {
	public static final int STATUS_OK =  0x9000;
	private static final int MAX_EXPECTED_BYTES_IN_RESPONSE = 256;

	private CardChannel cardChannel;
	private UserInterface userInterface;
	public CardCommunicationChannel(CardChannel cardChannel, UserInterface userInterface) {
		this.cardChannel = cardChannel;
		this.userInterface = userInterface;
	}
	
	public ResponseAPDU getBalance() {
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_GET_BALANCE, 0x00, 0x00, new byte[] {}, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU selectApplet() {
		CommandAPDU command = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, 
				AID.from(SecurePaymentCardClient.sAID_AppletInstance).toBytes(), MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU credit(byte value, byte antiReplayAttacksCounter, Signature serverdSignatureObject) {
		byte[] dataWithoutSignature = new byte[] {value, antiReplayAttacksCounter};
		byte[] data = Util.createByteArrayWithSignature(dataWithoutSignature, serverdSignatureObject);

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_CREDIT, 0x00, 0x00, data, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU debit(byte value, byte antiReplayAttacksCounter, Signature serverdSignatureObject) {	
		byte[] dataWithoutSignature = new byte[] {value, antiReplayAttacksCounter};
		byte[] data = Util.createByteArrayWithSignature(dataWithoutSignature, serverdSignatureObject);

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_DEBIT, 0x00, 0x00, data, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	public ResponseAPDU getPublicKey() {
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_GET_PUBLIC_KEY, 0x00, 0x00, new byte[] {}, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	public ResponseAPDU getSecurePayementCardID() {
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_GET_PAYEMENT_CARD_ID, 0x00, 0x00, new byte[] {}, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	
	public ResponseAPDU putPublicKey(ECPublicKey serverPublicKey) {
		byte[] encodedPublicKey = Crypto.getByteArrayFromPublicKey(serverPublicKey);
		
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_PUT_PUBLIC_KEY, 0x00, 0x00, encodedPublicKey, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU verifyUserPin(byte[] pin) {
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_VERIFY_PIN, 0x00, 0x00, pin);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	public void deploy(AMSession deployObject) {
		List<ResponseAPDU> responses = deployObject.run(cardChannel);	
		for(int i = 0; i < responses.size(); i++) {
			ResponseAPDU response = responses.get(i);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
		}
	}
	
	public void undeploy(AMService applicationManagementService) {
		AMSession undeploy = applicationManagementService.openSession(SecurePaymentCardClient.isdAID); 
		undeploy.uninstall(SecurePaymentCardClient.sAID_AppletInstance);
		undeploy.unload(SecurePaymentCardClient.sAID_CAP); 
		undeploy.close();
		
		List<ResponseAPDU> responses = undeploy.run(cardChannel);
		for(int i = 0; i < responses.size(); i++) {
			ResponseAPDU response = responses.get(i);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
		}
	}
}
