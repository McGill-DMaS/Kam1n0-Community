/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.kam1n0.framework.storage;

import java.io.Closeable;
import java.io.Serializable;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra.ObjectFactoryCassandra;

/**
 * Each object has a unique id. Supported types: int, long, float, double,
 * string, byte[], list<>, set<> As well as any field marked as @AsByte . Basic
 * attributes refer to meta data of primitive types. Some attributes such as
 * list or set sometimes is costly to retrieve and for some query we can leave
 * them empty. Any set, byte[], and list are considered non-basic (not
 * meta-data).
 *
 * @param <T>
 */
public abstract class ObjectFactoryMultiTenancy<T> implements Closeable, Serializable {
	private static final long serialVersionUID = 4316007564225032676L;

	/**
	 * Initialize the factory given the template class as well as the app name. User
	 * isolation is handled through the application level.
	 * 
	 * @param app
	 * @param clazz
	 * @throws Exception
	 */
	public abstract void initChild() throws Exception;

	/**
	 * The close the underlying factory and release any associated resources.
	 */
	public abstract void close();

	/**
	 * Add an object into database. rid is used for repository isolation.
	 * 
	 * @param rid
	 * @param obj
	 */
	public abstract void put(long rid, T obj, boolean async);

	public void put(long rid, T obj) {
		put(rid, obj, true);
	}

	/**
	 * Get an object with its full key. keys follow (primary key, secondary
	 * key....). As an object is identified by its full key, here we return only a
	 * single instance.
	 * 
	 * @param rid
	 * @param keys
	 * @return
	 */
	public abstract T querySingle(long rid, Object... keys);

	public abstract T querySingleBaisc(long rid, Object... keys);

	/**
	 * Get list of object with its partial keys. keys follow (primary key, secondary
	 * key....). Return any instance that satisfies the given partial key.
	 * 
	 * @param rid
	 * @param keys
	 * @return
	 */
	public abstract JavaRDD<T> queryMultiple(long rid, Object... keys);

	public abstract JavaRDD<T> queryMultipleBaisc(long rid, Object... keys);

	public abstract JavaRDD<T> queryMultiple(long rid, Map<String, ? extends Object> keys);

	public abstract JavaRDD<T> queryMultipleBaisc(long rid, Map<String, ? extends Object> keys);

	public abstract JavaRDD<T> queryMultiple(long rid, String fieldName, Collection<? extends Object> keys);

	public abstract JavaRDD<T> queryMultipleBaisc(long rid, String fieldName, Collection<? extends Object> keys);

	public abstract Iterable<T> browse();

	public abstract Iterable<T> browse(long rid);

	/**
	 * Delete according to full or partial key. Use with caution. If only the
	 * partial key is supplied, all records with that partial key will be deleted.
	 * 
	 * @param rid
	 * @param keys
	 * @return
	 */
	public abstract boolean del(long rid, Object... keys);

	/**
	 * Add an object to a specific collection list.
	 * 
	 * @param rid
	 * @param collectionName
	 * @param value
	 * @return
	 */
	public abstract boolean addToCollection(long rid, String collectionName, Object value, Object... fullKey);

	/**
	 * Count/Track number of records for a given user.
	 * 
	 * @param rid
	 * @return
	 */
	public abstract long count(long rid);

	/**
	 * Check existance of an object;
	 * 
	 * @return
	 */
	public abstract boolean check(long rid, Object... fullKey);

	public abstract void dump();
	
	public void prioritize() {};

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public static @interface KeyedSecondary {
		int index() default 0;
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public static @interface KeyedPrimary {
		int index() default 0;
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public static @interface AsBytes {
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public static @interface AsString {
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public static @interface AsBasic {
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public static @interface InnerAsString {
	}

	public static int checkPrimary(Field field) {
		KeyedPrimary ann = field.getAnnotation(KeyedPrimary.class);
		if (ann == null)
			return -1;
		else
			return ann.index();
	}

	public static boolean checkAsBytes(Field field) {
		return field.getAnnotation(AsBytes.class) != null;
	}

	public static boolean checkAsString(Field field) {
		return field.getAnnotation(AsString.class) != null;
	}

	public static boolean checkAsBaisc(Field field) {
		return field.getAnnotation(AsBasic.class) != null;
	}

	public static boolean checkInnerAsString(Field field) {
		return field.getAnnotation(InnerAsString.class) != null;
	}

	public static int checkSecondary(Field field) {
		KeyedSecondary ann = field.getAnnotation(KeyedSecondary.class);
		if (ann == null)
			return -1;
		else
			return ann.index();
	}

	protected static class FieldInformation implements Serializable {
		private static final long serialVersionUID = -3015385185713463036L;
		public String name = StringResources.STR_EMPTY;
		public String type = StringResources.STR_EMPTY;
		public boolean isList = false;
		public boolean isSet = false;
		public boolean innerAsString = false;

		public boolean asByte = false;
		public boolean asString = false;
		public boolean isBasic = true;

		public int idxPrimary = -1;
		public int idxSecondary = -1;

		@Override
		public String toString() {
			try {
				return mapper.writeValueAsString(this);
			} catch (JsonProcessingException e) {
				return super.toString();
			}
		}

		public FieldInformation(Field field) {
			idxPrimary = checkPrimary(field);
			idxSecondary = checkSecondary(field);
			asByte = checkAsBytes(field);
			asString = checkAsString(field);
			name = field.getName();
			Class<?> fieldType = field.getType();
			if (asByte) {
				type = "blob";
				isBasic = false;
			} else if (asString) {
				type = "text";
			} else if (Set.class.isAssignableFrom(fieldType)) {
				Class<?> pType = (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
				innerAsString = checkInnerAsString(field);
				if (innerAsString)
					type = "set<text>";
				else {
					String param = getBasicType(pType);
					type = "set<" + param + ">";
				}
				isSet = true;
				isBasic = false;

			} else if (List.class.isAssignableFrom(fieldType)) {
				Class<?> pType = (Class<?>) ((ParameterizedType) field.getGenericType()).getActualTypeArguments()[0];
				innerAsString = checkInnerAsString(field);
				if (innerAsString)
					type = "list<text>";
				else {
					String param = getBasicType(pType);
					type = "list<" + param + ">";
				}
				isList = true;
				isBasic = false;
			} else {
				type = getBasicType(fieldType);
				if (type.equals("blob"))
					isBasic = false;
			}
			// force as basic attributre
			if (checkAsBaisc(field))
				isBasic = true;

		}

		private static String getBasicType(Class<?> type) {
			if (type.isArray()) {
				if (type.getComponentType().getName().equals("byte"))
					return "blob";
			}
			switch (type.getName()) {
			case "java.lang.Integer":
			case "int":
				return "int";
			case "java.lang.Long":
			case "long":
				return "bigint";
			case "java.lang.Float":
			case "float":
				return "float";
			case "java.lang.Double":
			case "double":
				return "double";
			case "java.lang.String":
				return "text";
			case "java.lang.Boolean":
			case "boolean":
				return "Boolean";
			default:
				break;
			}
			logger.error("Unsupported type: {}", type);
			return null;
		}

		public boolean isCollection() {
			return isList || isSet;
		}

		public boolean isBasic() {
			return isBasic;
		}
	}

	protected final static ObjectMapper mapper = new ObjectMapper();
	protected final static String primaryKey_rid = "rid_0";
	private final static Logger logger = LoggerFactory.getLogger(ObjectFactoryCassandra.class);

	protected Map<String, FieldInformation> allAttributes = new HashMap<>();
	protected List<FieldInformation> secondaryKey = new ArrayList<>();
	protected List<FieldInformation> primaryKeys = null;
	protected String[] basicAttributes = null;
	protected Set<String> collectionAttributes = null;
	protected List<String> queryConditions = new ArrayList<>();

	protected String name_cl = StringResources.STR_EMPTY;
	protected String name_db = StringResources.STR_EMPTY;
	protected String app = StringResources.STR_EMPTY;
	protected Class<T> clazz;

	/**
	 * A distinct storage should be created per /global/app/clazz scope.
	 * 
	 * @param name_db
	 *            The global factory scope. Everything will under this scope.
	 * @param app
	 *            The application scope.
	 * @param clazz
	 *            The class scope.
	 * @throws Exception
	 */
	public void init(String name_db, String app, Class<T> clazz) throws Exception {
		this.app = app;
		this.clazz = clazz;
		this.name_db = name_db;
		this.name_cl = app + "_" + clazz.getSimpleName().toLowerCase();

		// collect field information; skip transient field.
		allAttributes = Arrays.stream(clazz.getFields()).filter(field -> !Modifier.isTransient(field.getModifiers()))
				.map(field -> new FieldInformation(field)).collect(Collectors.toMap(info -> info.name, info -> info));

		// check attributes and keys
		List<String> basics = allAttributes.values().stream().filter(FieldInformation::isBasic)
				.map(tp3 -> tp3.name.toLowerCase()).collect(Collectors.toList());
		List<String> collections = allAttributes.values().stream().filter(FieldInformation::isCollection)
				.map(tp3 -> tp3.name).collect(Collectors.toList());
		basicAttributes = basics.toArray(new String[basics.size()]);
		collectionAttributes = new HashSet<>(collections);

		secondaryKey = allAttributes.values().stream().filter(tp3 -> tp3.idxSecondary >= 0)
				.sorted((i1, i2) -> Integer.compare(i1.idxSecondary, i2.idxSecondary)).collect(Collectors.toList());

		primaryKeys = allAttributes.values().stream().filter(tp3 -> tp3.idxPrimary >= 0)
				.sorted((i1, i2) -> Integer.compare(i1.idxPrimary, i2.idxPrimary)).collect(Collectors.toList());

		initChild();
	}

}
