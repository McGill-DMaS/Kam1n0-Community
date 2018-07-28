package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index;

import java.io.Serializable;

import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;

public interface VecObject<T extends VecInfo, K extends VecInfoShared> extends Serializable {

	/**
	 * Hash based on content. Used to de-duplicate objects. Not strict. For example,
	 * hash on a vector. Objects sharing same vector is duplicated, but they have
	 * different meta data.
	 * 
	 * @return
	 */
	public long getUniqueHash();

	/**
	 * Get a an calculator class that can calculate the full key of this object.
	 * Using the hashSchema. The calculator will be called or will not be called,
	 * determined by the usage. Thus, it is like in a lazy way, not calculating the
	 * costly hashing, until it is needed.
	 * 
	 * @param hashSchema
	 * @return
	 */
	public VecFullKeyCalculator getFullKeyCalculator(HashSchema hashSchema);

	/**
	 * Some shared information will be used later, among those duplicated object
	 * with different meta-data.
	 * 
	 * @return
	 */
	public K getSharedInfo();

	/**
	 * Get meta-data of this object, not those shared fields (such as vector)
	 * 
	 * @return
	 */
	public T getSelfInfo();

	public byte[] hash(HashSchema schema);
}
