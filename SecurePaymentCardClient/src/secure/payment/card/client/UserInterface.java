package secure.payment.card.client;

public interface UserInterface {	
	public void sendMessageToUser(String message);
	public void sendMessageToUserIfDebug(String message);
	public void sendMessageToUserIfVerbose(String message);

}
