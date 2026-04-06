package secure.payment.card.client;

import java.io.IOException;
import java.util.Properties;

import javax.smartcardio.CardChannel;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import com.oracle.javacard.ams.AMSession;
import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.AMServiceFactory;
import com.oracle.javacard.ams.config.CAPFile;

import secure.payment.card.client.HttpPayload.HttpResponseBodyUnionType;
import secure.payment.card.client.HttpPayload.SecurePaymentCardCreationResponse;



public abstract class ClientUserInterface implements UserInterface {
	protected boolean debug;
	protected AMService applicationManagementService;
	protected SessionUserInterface sessionUserInterface;
	protected CardCommunicationChannel cardCommunicationChannel;
	protected ServerCommunicationChannel serverCommunicationChannel;

	public ClientUserInterface(CardChannel cardChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug) {
		this.debug = debug;
		this.sessionUserInterface = null;
		this.applicationManagementService = null;
		this.serverCommunicationChannel = serverCommunicationChannel;
		this.cardCommunicationChannel = new CardCommunicationChannel(cardChannel, this);
	}
	
	protected AMService initApplicationManagementService(String propertiesFilePath) {
		FileInputStream propertiesFile = null;
		Properties properties = new Properties();
		AMService applicationManagementService = null;
				
		try {
			propertiesFile = new FileInputStream(propertiesFilePath);
		} catch (FileNotFoundException e) {
			System.out.println("FileNotFoundException"); // TODO 
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		try {
			properties.load(propertiesFile);
		} catch (IOException e) {
			System.out.println("IOException"); // TODO 
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		try {
			applicationManagementService = AMServiceFactory.getInstance("GP2.2");
			applicationManagementService.setProperties(properties);
			// debugApplicationManagementService(applicationManagementService);
		} catch (NoSuchProviderException e) {
			System.out.println("NoSuchProviderException"); // TODO 
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
				
		return applicationManagementService;
	}
	
	protected AMSession createDeployObject(String capFileAid, String capFilePath, byte[] pin, String securePayementCardID) {
		CAPFile capFile = null;
		try {
			capFile = CAPFile.from(capFilePath);
		} catch (IOException e) {
			System.out.println(""); // TODO 
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		AMSession deploy = applicationManagementService.openSession(SecurePaymentCardClient.isdAID);  
		try {
			deploy.load(SecurePaymentCardClient.sAID_CAP, capFile.getBytes());  
		} catch (IOException e) {
			System.out.println(""); // TODO 
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}  
		
		byte[] installationParameters = Util.concatArrays(pin, securePayementCardID.getBytes());
		deploy.install(SecurePaymentCardClient.sAID_CAP, SecurePaymentCardClient.sAID_AppletClass, SecurePaymentCardClient.sAID_AppletInstance, installationParameters); 
		deploy.close();
		return deploy;
	}
	
	protected String registerNewSecurePayementCard()  {
		String securePayementCardID = null;
		
		KeyPair keyPair = Crypto.generateKeyPair();
		Signature signatureObject = Crypto.setSignatureAlgorithm();
		if (signatureObject == null) {
			System.out.println("Signature.getInstance : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		if(!Crypto.serverSignatureInitSign(signatureObject, (ECPrivateKey) keyPair.getPrivate())) {
			System.out.println("serverSignatureInitSign() : Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		byte[] publicKey = Crypto.getByteArrayFromPublicKey((ECPublicKey) keyPair.getPublic());
		byte[] signature = Crypto.signMessage(signatureObject, new byte[] {0x00});
		HttpResponseBodyUnionType<SecurePaymentCardCreationResponse> httpResponse = 
				serverCommunicationChannel.sendSecurePaymentCardRecord(publicKey, signature);
		
		if (!httpResponse.isError()) {
			securePayementCardID = httpResponse.getExpectedResponseBody().securePaymentCardId;
		} 		
		
		return securePayementCardID;
	}
	
	protected abstract void run();
	protected abstract byte[] getUserPin();
	protected abstract String getCapFilePath();
	protected abstract String getPropertiesFilePath();
	protected abstract SessionUserInterface startSession();
	public abstract void sendMessageToUser(String message);
	public abstract void sendMessageToUserIfDebug(String message);
}
