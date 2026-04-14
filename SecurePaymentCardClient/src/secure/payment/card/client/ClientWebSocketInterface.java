package secure.payment.card.client;

import secure.payment.card.client.JsonPayload.AuthenticationRequest;

public class ClientWebSocketInterface extends ClientUserInterface {	

	public ClientWebSocketInterface(String serverBaseUrl, String host, int port, boolean debug, boolean verbose) {
		super(serverBaseUrl, host, port, debug, verbose);
	}

	@Override
	protected void run() {
		
    }


	@Override
	protected SessionUserInterface startSession() {
		sessionUserInterface = new SessionWebSocketInterface(cardCommunicationChannel, serverCommunicationChannel, debug, verbose);
		return sessionUserInterface;
	}

	@Override
	protected byte[] getUserPin() {
		byte[] userPin = SecurePaymentCardClient.webSocketCommunicationChannel.userPin;
		if (userPin == null) {
			sendMessageToUser("Il est obligatoire de saisir un code PIN");
			return new byte[] {0x00};
		}
		
		SecurePaymentCardClient.webSocketCommunicationChannel.userPin = null;
		return userPin;
	}

	@Override
	protected String getCapFilePath() {
		return Util.getArg(SecurePaymentCardClient.cmdArgs, "cap", "");
	}

	@Override
	protected String getPropertiesFilePath() {
		return Util.getArg(SecurePaymentCardClient.cmdArgs, "props", "");
	}
	
	@Override
	public void sendMessageToUser(String message) {
		if (message.trim().equals("\n")) {
			System.out.println(message);		
			return;
		}
		
		if (SecurePaymentCardClient.webSocketCommunicationChannel != null) {
			System.out.println(message);		
			SecurePaymentCardClient.webSocketCommunicationChannel.broadcast(message);
		} else {
			System.out.println(message);		
		}
	}

	@Override
	public void sendMessageToUserIfDebug(String message) {
		if (debug) {
			System.out.println(message);
		}
	}
	
	@Override
	public void sendMessageToUserIfVerbose(String message) {
		if (verbose) {
			sendMessageToUser(message);
		}
	}

	@Override
	protected AuthenticationRequest createServerAuthenticationRequestObject() {
		AuthenticationRequest authenticationRequest = SecurePaymentCardClient.webSocketCommunicationChannel.authenticationRequest;
		if (authenticationRequest == null) {
			sendMessageToUser("Il est obligatoire de saisir une adresse mail et "
					+ "un mot de passe pour s'authentifier auprès du serveur.");
			return new AuthenticationRequest("", "");
		}
		
		return authenticationRequest;
	}
}