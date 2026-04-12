package secure.payment.card.client;

import java.util.List;
import java.util.ArrayList;

import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.cert.CertificateEncodingException;

import javax.crypto.Cipher;
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
	
	public ResponseAPDU sendCommand(CommandAPDU command) {
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU keyAgreement(ECPublicKey clientPublicKey) {
		byte[] encodedPublicKey = Crypto.getByteArrayFromPublicKey(clientPublicKey);

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_CLIENT_CARD_KEY_AGREEMENT, 0x00, 0x00, encodedPublicKey, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU getBalance(byte antiReplayAttacksCounter, Signature serverdSignatureObject, Cipher aesCipherEncryptObject) {
		byte[] dataWithoutSignature = new byte[] {antiReplayAttacksCounter};
		byte[] data = Util.createByteArrayWithSignature(dataWithoutSignature, serverdSignatureObject);
		
		byte[] encryptedData = Crypto.encryptAes(aesCipherEncryptObject, data);
		if (encryptedData == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_GET_BALANCE, 0x00, 0x00, encryptedData, MAX_EXPECTED_BYTES_IN_RESPONSE);
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
		CommandAPDU command = new CommandAPDU(0x00, SecurePaymentCardConstants.INS_SELECT, 0x04, 0x00, 
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
	
	public ResponseAPDU sendChallengeResponse(byte challengeResponse[]) {
		if (challengeResponse.length <= 255) {
			CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
					SecurePaymentCardConstants.INS_CHALLENGE_RESPONSE, 0x00, 0x00, challengeResponse, MAX_EXPECTED_BYTES_IN_RESPONSE);
			userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
			
			try {
				ResponseAPDU response = cardChannel.transmit(command);
				userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
				return response;
			} catch (CardException e) {
				return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
			}
		} else if (challengeResponse.length == 256) {
			byte[] tmp = new byte[challengeResponse.length - 1];
			System.arraycopy(challengeResponse, 1, tmp, 0, challengeResponse.length - 1);
			
			CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
					SecurePaymentCardConstants.INS_CHALLENGE_RESPONSE, 0x00, challengeResponse[0], tmp, MAX_EXPECTED_BYTES_IN_RESPONSE);
			userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
			
			try {
				ResponseAPDU response = cardChannel.transmit(command);
				userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
				return response;
			} catch (CardException e) {
				return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
			}
		} else {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	public ResponseAPDU credit(byte value, byte antiReplayAttacksCounter, Signature serverdSignatureObject, Cipher aesCipherEncryptObject) {
		byte[] dataWithoutSignature = new byte[] {value, antiReplayAttacksCounter};
		byte[] data = Util.createByteArrayWithSignature(dataWithoutSignature, serverdSignatureObject);
		
		byte[] encryptedData = Crypto.encryptAes(aesCipherEncryptObject, data);
		if (encryptedData == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_CREDIT, 0x00, 0x00, encryptedData, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU debit(byte value, byte antiReplayAttacksCounter, Signature serverdSignatureObject, Cipher aesCipherEncryptObject) {	
		byte[] dataWithoutSignature = new byte[] {value, antiReplayAttacksCounter};
		byte[] data = Util.createByteArrayWithSignature(dataWithoutSignature, serverdSignatureObject);
		
		byte[] encryptedData = Crypto.encryptAes(aesCipherEncryptObject, data);
		if (encryptedData == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_DEBIT, 0x00, 0x00, encryptedData, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	public ResponseAPDU getPublicKey(byte antiReplayAttacksCounter, Cipher aesCipherEncryptObject) {
		byte[] data = new byte[] {antiReplayAttacksCounter};
		byte[] encryptedData = Crypto.encryptAes(aesCipherEncryptObject, data);
		if (encryptedData == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_GET_SIG_PUBLIC_KEY, 0x00, 0x00, encryptedData, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	public ResponseAPDU getSecurePayementCardID(byte antiReplayAttacksCounter, Signature serverdSignatureObject, Cipher aesCipherEncryptObject) {
		byte[] dataWithoutSignature = new byte[] {antiReplayAttacksCounter};
		byte[] data = Util.createByteArrayWithSignature(dataWithoutSignature, serverdSignatureObject);
		
		byte[] encryptedData = Crypto.encryptAes(aesCipherEncryptObject, data);
		if (encryptedData == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
		
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_GET_PAYEMENT_CARD_ID, 0x00, 0x00, encryptedData, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}

	public ResponseAPDU putPublicKey(ECPublicKey clientPublicKey, byte antiReplayAttacksCounter, Cipher aesCipherEncryptObject) {
		byte[] encodedPublicKey = Crypto.getByteArrayFromPublicKey(clientPublicKey);
		
		byte[] data = new byte[encodedPublicKey.length + 1];
		System.arraycopy(encodedPublicKey, 0, data, 0, encodedPublicKey.length);
		data[data.length - 1] = antiReplayAttacksCounter;
		
		byte[] encryptedData = Crypto.encryptAes(aesCipherEncryptObject, data);
		if (encryptedData == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
		
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_PUT_SIG_PUBLIC_KEY, 0x00, 0x00, encryptedData, MAX_EXPECTED_BYTES_IN_RESPONSE);
		userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		
		try {
			ResponseAPDU response = cardChannel.transmit(command);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			return response;
		} catch (CardException e) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
	}
	
	public ResponseAPDU verifyUserPin(byte[] pin, byte antiReplayAttacksCounter, Signature serverdSignatureObject, Cipher aesCipherEncryptObject) {
		byte[] dataWithoutSignature = new byte[pin.length + 1];
		System.arraycopy(pin, 0, dataWithoutSignature, 0, pin.length);
		dataWithoutSignature[dataWithoutSignature.length - 1] = antiReplayAttacksCounter;
		
		byte[] data = Util.createByteArrayWithSignature(dataWithoutSignature, serverdSignatureObject);
		byte[] encryptedData = Crypto.encryptAes(aesCipherEncryptObject, data);
		if (encryptedData == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}

		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_VERIFY_PIN, 0x00, 0x00, encryptedData, MAX_EXPECTED_BYTES_IN_RESPONSE);
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
	
	public ResponseAPDU sendClientCertificate(X509Certificate certificate) {		
		try {
			byte[] certificateBytes = certificate.getEncoded();
			ArrayList<CommandAPDU> commands = splitPayload(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
					SecurePaymentCardConstants.INS_SEND_CLIENT_CERTIFICATE, certificateBytes);
			return sendCommands(commands);
		} catch (CertificateEncodingException e) {
			userInterface.sendMessageToUserIfDebug(String.format("%s : %s", e.getClass().toString(), e.getMessage()));
		}
		return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
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
	
	public ArrayList<CommandAPDU> splitPayload(byte commandCLA, byte commandINS, byte[] payload) {		
		ArrayList<CommandAPDU> commands = new ArrayList<CommandAPDU>();
		int commandDataMaxSize = 120;
			
		for(int i = 0, j = 0; i < payload.length; i += commandDataMaxSize, j++) {
			int start = i;
			int end = (i + commandDataMaxSize) >= payload.length ? payload.length : (i + commandDataMaxSize);
			int isLastPayload = (i + commandDataMaxSize) >= payload.length ? 0x01 : 0x00;

			byte[] buffer = new byte[end - start];
			System.arraycopy(payload, start, buffer, 0, end - start);
			
			byte p1 = 0x00;
			if (isLastPayload == 0x01) {
				p1 = (byte) 0x01;
			}

			CommandAPDU command = new CommandAPDU(commandCLA, commandINS, p1, (byte) j, buffer, 
					MAX_EXPECTED_BYTES_IN_RESPONSE);
			commands.add(command);	
		}	
		
		return commands;
	}
	
	public ResponseAPDU sendCommands(ArrayList<CommandAPDU> commands) {
		try {
			for(CommandAPDU command : commands) {
				userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
				
				ResponseAPDU response = cardChannel.transmit(command);
				userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
				if (response.getSW() != STATUS_OK || command.getP1() == 0x01) {
					return response;
				}
			}
		} catch (CardException e) {
			userInterface.sendMessageToUserIfDebug(String.format("%s : %s", e.getClass().toString(), e.getMessage()));
		}
		return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
	}

}