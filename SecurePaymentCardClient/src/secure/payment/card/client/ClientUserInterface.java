package secure.payment.card.client;

import java.util.Properties;
import javax.smartcardio.CardChannel;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import java.security.Security;
import java.security.KeyPair;
import java.security.Signature;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import com.oracle.javacard.ams.AMSession;
import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.config.CAPFile;
import com.oracle.javacard.ams.AMServiceFactory;

import secure.payment.card.client.HttpPayload.AuthenticationRequest;
import secure.payment.card.client.HttpPayload.AuthenticationResponse;
import secure.payment.card.client.HttpPayload.HttpResponseBodyUnionType;
import secure.payment.card.client.HttpPayload.SecurePaymentCardCreationResponse;

public abstract class ClientUserInterface implements UserInterface {
	private JavaCardClient javaCardClient;
	private AMService applicationManagementService;

	protected boolean debug;
	protected boolean verbose;
	protected SessionUserInterface sessionUserInterface;
	protected CardCommunicationChannel cardCommunicationChannel;
	protected ServerCommunicationChannel serverCommunicationChannel;

	public ClientUserInterface(String serverBaseUrl, String host, int port, boolean debug, boolean verbose) {
		this.debug = debug;
		this.verbose = verbose;
		
		this.serverCommunicationChannel = new ServerCommunicationChannel(serverBaseUrl, this);

		this.javaCardClient = new JavaCardClient(host, port, this);
		CardChannel cardChannel = javaCardClient.getCardChannel();
		
		sendMessageToUserIfDebug(String.format("ATR: [%s] \n", Util.convertByteArrayToString(javaCardClient.getATR())));
		
		this.sessionUserInterface = null;
		this.applicationManagementService = null;
		this.cardCommunicationChannel = new CardCommunicationChannel(cardChannel, this);
		
		AuthenticationRequest authenticationRequest = createServerAuthenticationRequestObject();
		if (authenticationRequest == null) {
			sendMessageToUser("Les informations nécessaires pour effectuer une demande "
					+ "d'authentification auprès du serveur sont introuvables.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		sendMessageToUserIfVerbose("Authentification auprès du serveur ...");
		HttpResponseBodyUnionType<AuthenticationResponse> httpResponse = 
				serverCommunicationChannel.authentication(authenticationRequest);
		if (!httpResponse.isError()) {
			serverCommunicationChannel.setAccessToken(httpResponse.getExpectedResponseBody().token);
			sendMessageToUserIfVerbose("L'authentification auprès du serveur a réussi.");
		} else {
			sendMessageToUser("L'authentification auprès du serveur a échoué.");
			sendMessageToUserIfDebug(httpResponse.getErrorResponse().toString());
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		Security.addProvider(new BouncyCastleProvider());		
	}
	
	private AMService initApplicationManagementService(String propertiesFilePath) {
		FileInputStream propertiesFile = null;
		Properties properties = new Properties();
		AMService applicationManagementService = null;
				
		try {
			propertiesFile = new FileInputStream(propertiesFilePath);
		} catch (FileNotFoundException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("initApplicationManagementService(), FileNotFoundException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		try {
			properties.load(propertiesFile);
		} catch (IOException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("initApplicationManagementService(), IOException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		try {
			applicationManagementService = AMServiceFactory.getInstance("GP2.2");
			applicationManagementService.setProperties(properties);
			// debugApplicationManagementService(applicationManagementService);
		} catch (NoSuchProviderException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("initApplicationManagementService(), NoSuchProviderException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
				
		return applicationManagementService;
	}
	
	private AMSession createDeployObject(String capFileAid, String capFilePath, byte[] pin, String securePayementCardID) {
		CAPFile capFile = null;
		try {
			capFile = CAPFile.from(capFilePath);
		} catch (IOException e) {
			sendMessageToUserIfDebug(String.format("createDeployObject(), IOException (1) : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		AMSession deploy = applicationManagementService.openSession(SecurePaymentCardClient.isdAID);  
		try {
			deploy.load(SecurePaymentCardClient.sAID_CAP, capFile.getBytes());  
		} catch (IOException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("createDeployObject(), IOException (2) : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}  
				
		byte[] installationParameters = Util.concatArrays(securePayementCardID.getBytes(), pin);

		deploy.install(SecurePaymentCardClient.sAID_CAP, SecurePaymentCardClient.sAID_AppletClass, 
				SecurePaymentCardClient.sAID_AppletInstance, installationParameters); 
		deploy.close();
		return deploy;
	}
	
	private String registerNewSecurePayementCard()  {
		String securePayementCardID = null;
		
		KeyPair keyPair = Crypto.generateKeyPair();
		Signature signatureObject = Crypto.setSignatureAlgorithm();
		if (signatureObject == null) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		if(!Crypto.signatureInitSign(signatureObject, (ECPrivateKey) keyPair.getPrivate())) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		byte[] publicKey = Crypto.getByteArrayFromPublicKey((ECPublicKey) keyPair.getPublic());
		byte[] signature = Crypto.signMessage(signatureObject, new byte[] {0x00, 0x00});
		HttpResponseBodyUnionType<SecurePaymentCardCreationResponse> httpResponse = 
				serverCommunicationChannel.sendSecurePaymentCardRecord(publicKey, signature);
		
		if (!httpResponse.isError()) {
			securePayementCardID = httpResponse.getExpectedResponseBody().securePaymentCardId;
		} 		
		
		return securePayementCardID;
	}
	
	protected void deploy() {
		if (applicationManagementService == null) {
			String propertiesFilePath = getPropertiesFilePath();
			applicationManagementService = initApplicationManagementService(propertiesFilePath);
		}
		
		byte[] pin = getUserPin();
		String capFilePath = getCapFilePath();
		
		String securePayementCardID = registerNewSecurePayementCard();
		if (securePayementCardID == null) {
			sendMessageToUser("Une erreur de communication avec le serveur a empêché l'enregistrement de la nouvelle carte.");
			return;
		}
		
		AMSession deployObject = createDeployObject(SecurePaymentCardClient.sAID_CAP, capFilePath, pin, securePayementCardID);
		
		sendMessageToUserIfDebug("Install");
		cardCommunicationChannel.deploy(deployObject);

	}
	
	protected void startOrResumeSession() {
		if (sessionUserInterface == null) {
			startSession();
		}
		sessionUserInterface.run();
	}
	
	protected void uninstall() {
		if (applicationManagementService == null) {
			String propertiesFilePath = getPropertiesFilePath();
			applicationManagementService = initApplicationManagementService(propertiesFilePath);
		}
		
		sendMessageToUserIfDebug("Uninstall");
		sendMessageToUserIfDebug("Unload");
		cardCommunicationChannel.undeploy(applicationManagementService);
		sessionUserInterface = null;
	}
	
	protected void disconnect() {
		javaCardClient.disconnect();
	}
	
	protected abstract void run();
	protected abstract byte[] getUserPin();
	protected abstract String getCapFilePath();
	protected abstract String getPropertiesFilePath();
	protected abstract SessionUserInterface startSession();
	public abstract void sendMessageToUser(String message);
	public abstract void sendMessageToUserIfDebug(String message);
	public abstract void sendMessageToUserIfVerbose(String message);
	protected abstract AuthenticationRequest createServerAuthenticationRequestObject();
}
