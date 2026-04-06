package secure.payment.card.client;

import java.lang.reflect.Type;
import java.lang.reflect.Field;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonSerializer;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonDeserializationContext;

public abstract class AbstractHttpPayload implements JsonSerializer<AbstractHttpPayload>, JsonDeserializer<AbstractHttpPayload> {
	
	public AbstractHttpPayload() {	
		
	}
	
	@Override
	public AbstractHttpPayload deserialize(JsonElement json, Type typeOfDst, JsonDeserializationContext context)
			throws JsonParseException {
		AbstractHttpPayload dst = null;
		JsonObject jsonObject = json.getAsJsonObject();
	
		Object object = Util.createNewObjectInstanceByTypeName(this.getClass().getTypeName());
		
		if (object != null) {
			dst = (AbstractHttpPayload) object;
			for (Field field : dst.getClass().getDeclaredFields()) {
				try {
					String fieldValue = jsonObject.get(field.getName()).getAsString();
					field.set(dst, fieldValue);
				} catch (IllegalArgumentException e) {
					System.out.println("IllegalArgumentException" + e.getMessage());
				} catch (IllegalAccessException e) {
					System.out.println("IllegalAccessException");
				}
			}
		} else {
			System.out.println("");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}

	    return dst;
	}

	@Override
	public JsonElement serialize(AbstractHttpPayload src, Type typeOfSrc, JsonSerializationContext context) {
		JsonObject jsonObject = new JsonObject();
		
		for (Field field : getClass().getDeclaredFields()) {
			try {
				jsonObject.addProperty(field.getName(), field.get(src).toString());
			} catch (IllegalArgumentException e) {
				System.out.println("IllegalArgumentException" + e.getMessage());
			} catch (IllegalAccessException e) {
				System.out.println("IllegalAccessException");
			}
		}

	    return jsonObject;
	}
}
