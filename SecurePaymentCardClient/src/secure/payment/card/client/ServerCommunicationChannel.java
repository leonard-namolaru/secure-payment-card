package secure.payment.card.client;

import java.io.IOException;
import java.lang.reflect.Type;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpTimeoutException;

import secure.payment.card.client.HttpPayload.ErrorResponse;
import secure.payment.card.client.HttpPayload.AuthenticationRequest;
import secure.payment.card.client.HttpPayload.AuthenticationResponse;
import secure.payment.card.client.HttpPayload.SecurePaymentCardRecord;
import secure.payment.card.client.HttpPayload.HttpResponseBodyUnionType;
import secure.payment.card.client.HttpPayload.SecurePaymentCardCreationResponse;

public class ServerCommunicationChannel {
	private String baseUrl;
	private String accessToken;
	private HttpClient httpClient;
	
	public enum HttpMethodEnum {GET, POST, PUT}
	
	public ServerCommunicationChannel(String baseUrl) {
		this.baseUrl = baseUrl;
		this.httpClient = HttpClient.newHttpClient();
		
		HttpResponseBodyUnionType<AuthenticationResponse> authenticationResponse = handleHttpRequest("/auth", HttpMethodEnum.POST, 
				new AuthenticationRequest(System.getenv("SUPER_ADMIN_EMAIL"), System.getenv("SUPER_ADMIN_PASSWORD")), new AuthenticationResponse(), false);
		if (!authenticationResponse.isError()) {
			this.accessToken = authenticationResponse.getExpectedResponseBody().token;
		} else {
			System.out.println(authenticationResponse.getErrorResponse());
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
	}
	
	public HttpResponseBodyUnionType<SecurePaymentCardCreationResponse> sendSecurePaymentCardRecord(byte[] publicKey, byte[] balanceSignature) {
    	String publicKeyHex = Util.bytesToHex(publicKey);
    	String balanceSignatureHex = Util.bytesToHex(balanceSignature);
    	SecurePaymentCardRecord securePaymentCardRecord = new SecurePaymentCardRecord(publicKeyHex, balanceSignatureHex);
    	
    	return handleHttpRequest("/api/v1/", HttpMethodEnum.POST, securePaymentCardRecord, new SecurePaymentCardCreationResponse(), true);
	}
	
	public <T extends AbstractHttpPayload, G extends AbstractHttpPayload> HttpResponseBodyUnionType<G> handleHttpRequest
	(String path, HttpMethodEnum httpMethod, T requestPayload, G expectedResponsePayloadClass, boolean useAccessToken) {
		
        Builder requestBuilder = HttpRequest.newBuilder();
        requestBuilder.uri(URI.create(baseUrl + path));
        requestBuilder.timeout(Duration.of(10, ChronoUnit.SECONDS));

        if (useAccessToken) {
            requestBuilder.headers("Authorization", String.format("Bearer %s", accessToken)); 
        }
                
		String requestBody = "";
		if (httpMethod == HttpMethodEnum.POST || httpMethod == HttpMethodEnum.PUT) {
	        requestBuilder.headers("Content-Type", "application/json");

			GsonBuilder httpRequestGsonBuilder = new GsonBuilder();			
			Object object = Util.createNewObjectInstanceByTypeName(requestPayload.getClass().getTypeName());
			if (object == null) {
				System.out.println("");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}
			
			Gson httpRequestGson = httpRequestGsonBuilder.registerTypeAdapter(requestPayload.getClass(), object).create();
	    	requestBody = httpRequestGson.toJson(requestPayload);
	    	System.out.println(requestBody);
		} 
        
		switch (httpMethod) {
			case GET: requestBuilder.GET();
				 break;
			case POST:requestBuilder.POST(HttpRequest.BodyPublishers.ofString(requestBody));
			     break;
			case PUT:requestBuilder.PUT(HttpRequest.BodyPublishers.ofString(requestBody));
		         break;
		}
        
        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = null;
		try {
			response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
		} catch (HttpTimeoutException e) {
			System.out.println("HttpTimeoutException : " + e.getMessage());
			response = null;
		} catch (IOException e) { 
			System.out.println("IOException : " + e.getMessage() + " " + e.getCause());
			response = null;
		} catch (InterruptedException e) {
			System.out.println("InterruptedException : " + e.getMessage());
			response = null;
		} 
		
		if (response != null) {
			GsonBuilder httpResponseGsonBuilder = new GsonBuilder();
			
			Type type = null;
			Object typeAdapter = null;
			boolean isErrorResponse = false;
			if (response.statusCode() >= 400 || response.statusCode() >= 500) {
				isErrorResponse = true;
				type = ErrorResponse.class;
				typeAdapter = new ErrorResponse();
			} else if (response.statusCode() >= 200) {
				type = expectedResponsePayloadClass.getClass();
				typeAdapter = Util.createNewObjectInstanceByTypeName(expectedResponsePayloadClass.getClass().getTypeName());
			} else {
				System.out.println("");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}
			
			if (typeAdapter == null) {
				System.out.println("");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}

			Gson httpResponseGson = null;
			httpResponseGson = httpResponseGsonBuilder.registerTypeAdapter(type, typeAdapter).create();

			System.out.println(response.body());
			
			HttpResponseBodyUnionType<G> httpResponseBodyUnionType = new HttpResponseBodyUnionType<>();
			Object httpResponseBody = null;
			try {
				httpResponseBody = httpResponseGson.fromJson(response.body(), type);
			} catch (JsonSyntaxException e) {
				System.out.println("");
				System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
			}

			if (isErrorResponse) {
				httpResponseBodyUnionType.setErrorResponse((ErrorResponse) httpResponseBody);
			} else {
				httpResponseBodyUnionType.setExpectedResponseBody((G) httpResponseBody);
			}
			
			return httpResponseBodyUnionType;
		}
		
		return null;
	}
}
