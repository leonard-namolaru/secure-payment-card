package secure.payment.card.client;

import java.util.List;
import java.net.InetSocketAddress;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardException;
import javax.smartcardio.TerminalFactory;

public class JavaCardClient {
	private Card card;
	UserInterface userInterface;
	private CardChannel cardChannel;
	private CardTerminal cardTerminal;
	private InetSocketAddress inetSocketAddress;
	
	public CardChannel getCardChannel() {
		return cardChannel;
	}
	
	public byte[] getATR() {
		return card.getATR().getBytes();
	}
	
	public boolean disconnect() {
		boolean result = true;
		try {
			card.disconnect(true);
		} catch (CardException e) {
			userInterface.sendMessageToUserIfDebug(String.format("disconnect(), CardException : %s", e.getMessage()));
			result = false;
		}
		
		return result;
	}
	
	public JavaCardClient(String host, int port, UserInterface userInterface) {
		this.userInterface = userInterface;
		
		this.inetSocketAddress = connectHost(host, port);
		if (inetSocketAddress == null) {
			this.userInterface.sendMessageToUser("La connexion a échoué");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.cardTerminal = getCardTerminal();
		if (cardTerminal == null) {
			this.userInterface.sendMessageToUser("La connexion a échoué.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		if (waitForCardPresent(10000)) {
			this.userInterface.sendMessageToUserIfVerbose(String.format("Connexion avec le terminal de carte établie."));
		} else {
			this.userInterface.sendMessageToUser("La connexion a échoué (timeout)");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		this.card = connectCard();
		if (card == null) {
			this.userInterface.sendMessageToUser("La connexion a échoué.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		this.cardChannel = getCardBasicChannel();
		if (cardChannel == null) {
			this.userInterface.sendMessageToUser("La connexion a échoué.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	}
	
	private InetSocketAddress connectHost(String host, int port) {
		InetSocketAddress inetSocketAddress = null;
		
		try {
			inetSocketAddress = new InetSocketAddress(host, port);
		} catch (SecurityException e) {
			userInterface.sendMessageToUser("Une erreur inattendue s'est produite.");
			userInterface.sendMessageToUserIfDebug(String.format("connectHost(), SecurityException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		if (inetSocketAddress.isUnresolved()) {
			inetSocketAddress = null;
		}
		
		return inetSocketAddress;
	}
	
	private CardTerminal getCardTerminal() {
	    // TerminalFactory terminalFactory = TerminalFactory.getDefault();
		TerminalFactory terminalFactory = null;
		try {
			terminalFactory = TerminalFactory.getInstance("SocketCardTerminalFactoryType",  
					List.of(inetSocketAddress), "SocketCardTerminalProvider");
		} catch (NoSuchAlgorithmException e) {
			userInterface.sendMessageToUser("Une erreur inattendue s'est produite.");
			userInterface.sendMessageToUserIfDebug(String.format("getCardTerminal(), NoSuchAlgorithmException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		} catch (NoSuchProviderException e) {
			userInterface.sendMessageToUser("Une erreur inattendue s'est produite.");
			userInterface.sendMessageToUserIfDebug(String.format("getCardTerminal(), NoSuchProviderException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	        
		List<CardTerminal> terminals = null;
		try {
			terminals = terminalFactory.terminals().list();
		} catch (CardException e) {
			userInterface.sendMessageToUser("Une erreur inattendue s'est produite.");
			userInterface.sendMessageToUserIfDebug(String.format("getCardTerminal(), CardException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	        
		CardTerminal cardTerminal = null;
		if (terminals.size() > 0) {
			cardTerminal = terminals.get(0);
		}
				
		return cardTerminal;
	}
	
	private boolean waitForCardPresent(long timeout) {
		userInterface.sendMessageToUserIfVerbose("Connexion avec le terminal de carte en cours ...");
		
		boolean result = true;
		try {
			if (!cardTerminal.waitForCardPresent(timeout)) {
				result = false;
			}
		} catch (CardException e) {
			userInterface.sendMessageToUser("La connexion a échoué");
			userInterface.sendMessageToUserIfDebug(String.format("waitForCardPresent(), SecurityException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		return result;		
	}
	
	private Card connectCard() {
		Card card = null;
		try {
			card = cardTerminal.connect("*");
		} catch (CardException e) {
			userInterface.sendMessageToUserIfDebug(String.format("connectCard(), CardException : %s", e.getMessage()));
			card = null;
		}
		
		return card;
	}
	
	private CardChannel getCardBasicChannel() {
		CardChannel cardChannel = null;
		try {
			cardChannel = card.getBasicChannel();
		} catch (SecurityException e) {
			userInterface.sendMessageToUserIfDebug(String.format("getCardBasicChannel(), SecurityException : %s", e.getMessage()));
			cardChannel = null;
		}
				
	    return cardChannel;		
	}
}
