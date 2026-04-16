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
		byte[] encodedPublicKey = Crypto.getByteArrayFromPublicKey(clientPublicKey, userInterface);
		if (encodedPublicKey == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
		
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
	
	
	public ResponseAPDU sendAndGetChallenge(byte challenge[]) {
		CommandAPDU command = new CommandAPDU(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
				SecurePaymentCardConstants.INS_GET_CHALLENGE, 0x00, 0x00, 
				challenge);
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
		byte[] encodedPublicKey = Crypto.getByteArrayFromPublicKey(clientPublicKey, userInterface);
		if (encodedPublicKey == null) {
			return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
		}
		
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
	
	public ResponseAPDU sendCertificate(byte commandINS, X509Certificate certificate) {		
		try {
			byte[] certificateBytes = certificate.getEncoded();
			ArrayList<CommandAPDU> commands = splitPayload(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
					commandINS, certificateBytes, (byte) 0x00);
			return sendCommands(commands);
		} catch (CertificateEncodingException e) {
			userInterface.sendMessageToUserIfDebug(String.format("%s : %s", e.getClass().toString(), e.getMessage()));
		}
		return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
	}
	
	public boolean undeploy(AMService applicationManagementService) {
		AMSession undeploy = applicationManagementService.openSession(SecurePaymentCardClient.isdAID); 
		undeploy.uninstall(SecurePaymentCardClient.sAID_AppletInstance);
		undeploy.unload(SecurePaymentCardClient.sAID_CAP); 
		undeploy.close();
		
		List<ResponseAPDU> responses = undeploy.run(cardChannel);
		
		boolean undeployOk = true;
		for(int i = 0; i < responses.size(); i++) {
			ResponseAPDU response = responses.get(i);
			userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			
			if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
				undeployOk = false;
			}
		}
		
		return undeployOk;
	}
	
	public ArrayList<CommandAPDU> splitPayload(byte commandCLA, byte commandINS, byte[] payload, byte p2) {		
		ArrayList<CommandAPDU> commands = new ArrayList<CommandAPDU>();
		int commandDataMaxSize = 120;
			
		for(int i = 0; i < payload.length; i += commandDataMaxSize) {
			int start = i;
			int end = (i + commandDataMaxSize) >= payload.length ? payload.length : (i + commandDataMaxSize);
			int isLastPayload = (i + commandDataMaxSize) >= payload.length ? 0x01 : 0x00;

			byte[] buffer = new byte[end - start];
			System.arraycopy(payload, start, buffer, 0, end - start);
			
			CommandAPDU command = new CommandAPDU(commandCLA, commandINS, (byte) isLastPayload, p2, buffer);
			commands.add(command);	
		}	
		
		return commands;
	}
	
	public ResponseAPDU sendCommands(ArrayList<CommandAPDU> commands) {
		byte[] responseBuffer = new byte[800];
		int responseDataOffset = 0;
		
		try {
			for(CommandAPDU command : commands) {
				userInterface.sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
				
				ResponseAPDU response = cardChannel.transmit(command);
				userInterface.sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
				if (response.getSW() != STATUS_OK) {
					return response;
				} 
				
				byte[] data = response.getData();
				if ((data.length + responseDataOffset) < responseBuffer.length) {
					System.arraycopy(data, 0, responseBuffer, responseDataOffset, data.length);
					responseDataOffset += data.length;
				}
				
				if (command.getP1() == 0x01) {
					byte[] responseBytes = new byte[responseDataOffset + 2];
					System.arraycopy(responseBuffer, 0, responseBytes, 0, responseDataOffset);
					
					byte[] sw = new byte[] {(byte) 0x90, 0x00};
					System.arraycopy(sw, 0, responseBytes, responseDataOffset, sw.length);
					return new ResponseAPDU(responseBytes);
				}
			}
		} catch (CardException e) {
			userInterface.sendMessageToUserIfDebug(String.format("%s : %s", e.getClass().toString(), e.getMessage()));
		}
		return new ResponseAPDU(new byte[] {0x00, 0x00, 0x00, 0x00});
	}

}