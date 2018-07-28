package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.indexer.VecInfoBlock;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.rep.VecInfoArray;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY)
@JsonSubTypes({ @JsonSubTypes.Type(value = VecInfoBlock.class, name = "B"),
		@JsonSubTypes.Type(value = VecInfoArray.class, name = "A") })
public abstract class VecInfo implements Serializable {
	private static final long serialVersionUID = -6014437255367842663L;
	private static ObjectMapper mapper = new ObjectMapper();

	public String serialize() {
		try {
			return mapper.writeValueAsString((VecInfo) this);
		} catch (JsonProcessingException e) {
			VecEntry.logger.error("Failed to serialize entryinfo.", e);
			return StringResources.STR_EMPTY;
		}
	}

	@SuppressWarnings("unchecked")
	public static <T extends VecInfo> T deSerialize(String str) {

		try {
			VecInfo obj = mapper.readValue(str, VecInfo.class);
			if (obj instanceof VecInfo)
				return (T) obj;
			else
				return null;
		} catch (Exception e) {
			VecEntry.logger.error("Failed to deserialize the vecEntryInfo.", e);
			return null;
		}
	}

	public static void main(String[] args) {
		VecInfoBlock block = new VecInfoBlock();
		block.functionId = 10000l;
		String blockstr = ((VecInfo) block).serialize();
		System.out.println(blockstr);
		VecInfoBlock block2 = VecInfo.deSerialize(blockstr);
		System.out.println(block2);
		System.out.println(block2.serialize());
	}

}