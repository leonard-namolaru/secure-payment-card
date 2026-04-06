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
			result = false;
		}
		
		return result;
	}
	
	public JavaCardClient(String host, int port) {
		this.inetSocketAddress = connectHost(host, port);
		if (inetSocketAddress == null) {
			System.out.println("connectHost : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		this.cardTerminal = getCardTerminal();
		if (cardTerminal == null) {
			System.out.println("cardTerminal : La connexion a échoué.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		if (waitForCardPresent(10000)) {
			System.out.println("Connexion établie : " + cardTerminal.getName());
		} else {
			System.out.println("La connexion a échoué");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		this.card = connectCard();
		if (card == null) {
			System.out.println("La connexion a échoué.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		this.cardChannel = getCardBasicChannel();
		if (cardChannel == null) {
			System.out.println("La connexion a échoué.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	}
	
	private InetSocketAddress connectHost(String host, int port) {
		InetSocketAddress inetSocketAddress = null;
		
		try {
			inetSocketAddress = new InetSocketAddress(host, port);
		} catch (SecurityException e) {
			System.out.println("InetSocketAddress : Une erreur inattendue s'est produite.");
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
			System.out.println("TerminalFactory.getInstance NoSuchAlgorithmException : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		} catch (NoSuchProviderException e) {
			System.out.println("TerminalFactory.getInstance NoSuchProviderException : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	        
		List<CardTerminal> terminals = null;
		try {
			terminals = terminalFactory.terminals().list();
		} catch (CardException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
	        
		CardTerminal cardTerminal = null;
		if (terminals.size() > 0) {
			cardTerminal = terminals.get(0);
		}
				
		return cardTerminal;
	}
	
	private boolean waitForCardPresent(long timeout) {
		System.out.println("Connexion en cours ...");
		
		boolean result = true;
		try {
			if (!cardTerminal.waitForCardPresent(timeout)) {
				result = false;
			}
		} catch (CardException e) {
			System.out.println("La connexion a échoué");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		return result;		
	}
	
	private Card connectCard() {
		Card card = null;
		try {
			card = cardTerminal.connect("*");
		} catch (CardException e) {
			card = null;
		}
		
		return card;
	}
	
	private CardChannel getCardBasicChannel() {
		CardChannel cardChannel = null;
		try {
			cardChannel = card.getBasicChannel();
		} catch (SecurityException e) {
			cardChannel = null;
		}
				
	    return cardChannel;		
	}
}
