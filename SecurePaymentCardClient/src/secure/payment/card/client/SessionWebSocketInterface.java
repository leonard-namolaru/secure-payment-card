package secure.payment.card.client;

public class SessionWebSocketInterface extends SessionUserInterface {

	public SessionWebSocketInterface(CardCommunicationChannel cardCommunicationChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug, boolean verbose) {
		super(cardCommunicationChannel, serverCommunicationChannel, debug, verbose);
	}

	@Override
	protected void run() {
		
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
}