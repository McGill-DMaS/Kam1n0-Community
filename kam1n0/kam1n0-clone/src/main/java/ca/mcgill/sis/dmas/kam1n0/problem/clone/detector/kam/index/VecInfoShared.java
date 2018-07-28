package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.indexer.VecInfoSharedBlock;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.rep.VecInfoSharedArray;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY)
@JsonSubTypes({ @JsonSubTypes.Type(value = VecInfoSharedBlock.class, name = "B"),
		@JsonSubTypes.Type(value = VecInfoSharedArray.class, name = "A") })
public abstract class VecInfoShared implements Serializable {

	private static final long serialVersionUID = 7158559399264706813L;

	private static ObjectMapper mapper = new ObjectMapper();

	public String serialize() {
		try {
			return mapper.writeValueAsString((VecInfoShared) this);
		} catch (JsonProcessingException e) {
			VecEntry.logger.error("Failed to serialize entryinfo.", e);
			return StringResources.STR_EMPTY;
		}
	}

	@SuppressWarnings("unchecked")
	public static <T extends VecInfoShared> T deSerialize(String str) {

		try {
			VecInfoShared obj = mapper.readValue(str, VecInfoShared.class);
			if (obj instanceof VecInfoShared)
				return (T) obj;
			else
				return null;
		} catch (Exception e) {
			VecEntry.logger.error("Failed to deserialize the vecEntryInfo.", e);
			return null;
		}
	}

}
