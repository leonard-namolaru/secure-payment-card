package secure.payment.card.client;

import java.net.InetSocketAddress;
import org.java_websocket.WebSocket;
import java.net.UnknownHostException;

import javax.xml.bind.helpers.ParseConversionEventImpl;

import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import secure.payment.card.client.JsonPayload.Transaction;
import secure.payment.card.client.JsonPayload.AuthenticationRequest;

public class WebSocketCommunicationChannel extends WebSocketServer {
	public static final String GUI_SEPARATOR_CHAR = "|";
	public static final int AUTHENTICATION_REQUEST = 0;
	public static final int DEPLOY = 1;
	public static final int START_OR_RESUME_SESSION = 2;
	public static final int UNINSTALL = 3;
	public static final int CLOSE_CLIENT_INTERFACE = 4;
	public static final int DEBIT = 5;
	public static final int CREDIT = 6;

	private boolean debug;
	private boolean verbose;
	private String serverBaseUrl;
	private int cardTerminalPort;
	private String cardTerminalHost;

	public WebSocket connection;
	public AuthenticationRequest authenticationRequest;
	private ClientWebSocketInterface clientWebSocketInterface;
	  
	public WebSocketCommunicationChannel(String serverBaseUrl, String cardTerminalHost, int cardTerminalPort, 
			boolean debug, boolean verbose, int webSocketPort) throws UnknownHostException {
		super(new InetSocketAddress(webSocketPort));
		
	    this.debug = debug;
	    this.verbose = verbose;
		this.serverBaseUrl = serverBaseUrl;
		this.cardTerminalHost = cardTerminalHost;
		this.cardTerminalPort = cardTerminalPort;
		
	    this.connection = null;
	    this.authenticationRequest = null;
	    this.clientWebSocketInterface = null;
	 }

	 @Override
	 public void onOpen(WebSocket connection, ClientHandshake handshake) {
		 if (this.connection == null) {
			 this.connection = connection;
		} else {
			connection.close();
		}
		
	    System.out.println("Nouvelle connexion : " + connection.getRemoteSocketAddress().getAddress().getHostAddress());
	 }

	 @Override
	 public void onClose(WebSocket connection, int code, String reason, boolean remote) {
		 this.connection = null;
	 }

	 @Override
	 public void onMessage(WebSocket conn, String message) {
		this.connection = conn;
		System.out.println(conn + ": " + message);

		 int separatorCharIndex = message.indexOf(GUI_SEPARATOR_CHAR);
		 if (separatorCharIndex == -1) {
			 broadcast("Le message reçu par le client via l'interface graphique ne correspond pas au format attendu.");
			 return;
		 }
		 
		 int messageTypeId = -1;
		 try {
			 messageTypeId =  Integer.parseInt(message.substring(0, separatorCharIndex));   
		 } catch (NumberFormatException e) {
			 broadcast("Le message reçu par le client via l'interface graphique ne contient pas d'identifiant valide.");
			 return;
		 }
		 
		 switch (messageTypeId) {
		 	case AUTHENTICATION_REQUEST: 
		 			GsonBuilder httpResponseGsonBuilder = new GsonBuilder();
		 			Gson httpResponseGson = httpResponseGsonBuilder.registerTypeAdapter(AuthenticationRequest.class, new AuthenticationRequest()).create();
		 			String payload = message.substring(separatorCharIndex + 1, message.length());
		 			
		 		    authenticationRequest = httpResponseGson.fromJson(payload, AuthenticationRequest.class);
				 	ClientWebSocketInterface clientWebSocketInterface = new ClientWebSocketInterface(serverBaseUrl, cardTerminalHost, 
						 cardTerminalPort, debug, verbose);
				 	this.clientWebSocketInterface = clientWebSocketInterface;
				 	break;
		 	case DEPLOY: 
		 		if (this.clientWebSocketInterface != null) {
		 			this.clientWebSocketInterface.deploy();
		 		} else {
					broadcast("Il est nécessaire de s'authentifier auprès du serveur avant d'effectuer cette opération.");
		 		}
		 	    break;
		 	case START_OR_RESUME_SESSION: 
		 		if (this.clientWebSocketInterface != null) {
		 			this.clientWebSocketInterface.startOrResumeSession();
		 		} else {
					broadcast("Il est nécessaire de s'authentifier auprès du serveur avant d'effectuer cette opération.");
		 		}
		 	    break;
		 	case UNINSTALL: 
		 		if (this.clientWebSocketInterface != null) {
		 			this.clientWebSocketInterface.uninstall();
		 		} else {
					broadcast("Il est nécessaire de s'authentifier auprès du serveur avant d'effectuer cette opération.");
		 		}
		 	    break;
		 	case CLOSE_CLIENT_INTERFACE: 
		 		if (this.clientWebSocketInterface != null) {
		 			this.clientWebSocketInterface = null;
		 		} else {
					broadcast("Il est nécessaire de s'authentifier auprès du serveur avant d'effectuer cette opération.");
		 		}
		 	    break;
		 	case DEBIT: 
		 		if (this.clientWebSocketInterface != null) {
		 			httpResponseGsonBuilder = new GsonBuilder();
		 			httpResponseGson = httpResponseGsonBuilder.registerTypeAdapter(Transaction.class, new Transaction()).create();
		 			payload = message.substring(separatorCharIndex + 1, message.length());
		 			Transaction transaction = httpResponseGson.fromJson(payload, Transaction.class);
		 			
		 			int amount = 0;
		 			try {
			 			amount = Integer.parseInt(transaction.amount);
		 			} catch (NumberFormatException e) {
						broadcast("Le montant de la transaction doit être une valeur numérique.");
		 				break;
		 			}

		 			if (this.clientWebSocketInterface.sessionUserInterface != null) {
		 				this.clientWebSocketInterface.sessionUserInterface.debit((byte) amount);
		 			} else {
						broadcast("Il est nécessaire de démarrer une session pour effectuer cette opération.");
		 			}
		 		} else {
					broadcast("Il est nécessaire de s'authentifier auprès du serveur avant d'effectuer cette opération.");
		 		}
		 	    break;	 	
		 	case CREDIT: 
		 		if (this.clientWebSocketInterface != null) {
		 			httpResponseGsonBuilder = new GsonBuilder();
		 			httpResponseGson = httpResponseGsonBuilder.registerTypeAdapter(Transaction.class, new Transaction()).create();
		 			payload = message.substring(separatorCharIndex + 1, message.length());
		 			Transaction transaction = httpResponseGson.fromJson(payload, Transaction.class);
		 			
		 			int amount = 0;
		 			try {
			 			amount = Integer.parseInt(transaction.amount);
		 			} catch (NumberFormatException e) {
						broadcast("Le montant de la transaction doit être une valeur numérique.");
		 				break;
		 			}
		 			
		 			if (this.clientWebSocketInterface.sessionUserInterface != null) {
		 				this.clientWebSocketInterface.sessionUserInterface.credit((byte) amount);
		 			} else {
						broadcast("Il est nécessaire de démarrer une session pour effectuer cette opération.");
		 			}
		 		} else {
					broadcast("Il est nécessaire de s'authentifier auprès du serveur avant d'effectuer cette opération.");
		 		}
		 	    break;	 			 	    
			default:
					broadcast("Le message reçu par le client via l'interface graphique contenait un identifiant invalide.");
				return;
		 }
	 }

	 @Override
	 public void onError(WebSocket conn, Exception ex) {
		this.connection = conn;

	    ex.printStackTrace();
	    if (conn != null) {
	      
	    }
	 }

	 @Override
	 public void onStart() {
	    System.out.println("Le serveur WebSocket a démarré.");
	 }
}