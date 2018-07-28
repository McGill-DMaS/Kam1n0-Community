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
package ca.mcgill.sis.dmas.kam1n0.impl.storage.ram;

import java.io.Serializable;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import javax.ws.rs.NotSupportedException;

import org.apache.spark.api.java.JavaRDD;
import org.apache.tools.ant.types.resources.StringResource;
import org.eclipse.cdt.internal.core.dom.parser.c.CLabel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.Environment.KamMode;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import scala.Tuple2;

public class ObjectFactoryRAM<T extends Serializable> extends ObjectFactoryMultiTenancy<T> {

	private static Logger logger = LoggerFactory.getLogger(ObjectFactoryRAM.class);
	private static final long serialVersionUID = -8051605145894646103L;
	public SparkInstance spark;

	HashMap<String, TreeMap<String, T>> db = new HashMap<>();
	HashMap<Long, Long> counts = new HashMap<>();

	public ObjectFactoryRAM(SparkInstance spark) {
		this.spark = spark;
	}

	private String KeysToString(ArrayList<Object> keys) {
		return StringResources.JOINER_TOKEN_DOT.join(keys);
	}

	private String getPrimaryKey(long uid, T obj) {
		try {
			ArrayList<Object> keys = new ArrayList<>();
			keys.add(uid);
			for (FieldInformation pk : primaryKeys) {
				keys.add(this.clazz.getField(pk.name).get(pk));
			}
			return KeysToString(keys);
		} catch (Exception e) {
			logger.error("Failed to get the primary key for " + obj, e);
			return null;
		}
	}

	private String getSecondaryKey(T obj) {
		try {
			ArrayList<Object> keys = new ArrayList<>();
			for (FieldInformation sk : secondaryKey) {
				keys.add(this.clazz.getField(sk.name).get(obj));
			}
			return KeysToString(keys);
		} catch (Exception e) {
			logger.error("Failed to get the primary key for " + obj, e);
			return null;
		}
	}

	private Tuple2<String, String> getKeys(long uid, Object... keys) {
		try {
			ArrayList<Object> pks = new ArrayList<>();
			ArrayList<Object> sks = new ArrayList<>();
			pks.add(uid);
			int i = 0;
			for (; i < primaryKeys.size(); ++i)
				pks.add(keys[i]);
			for (; i < keys.length; ++i)
				sks.add(keys[i]);
			String pk = KeysToString(pks);
			String sk = KeysToString(sks);
			return new Tuple2<String, String>(pk, sk);
		} catch (Exception e) {
			logger.error("Failed to parse keys " + Arrays.toString(keys), e);
			return null;
		}
	}

	@Override
	public void initChild() throws Exception {

	}

	@Override
	public void close() {

	}

	@Override
	public void put(long uid, T obj, boolean async) {
		String pk = getPrimaryKey(uid, obj);
		String sk = getSecondaryKey(obj);
		synchronized (db) {
			db.compute(pk, (k, v) -> {
				if (v == null)
					v = new TreeMap<>();
				v.put(sk, obj);
				return v;
			});
			counts.compute(uid, (k, v) -> v == null ? 1 : v + 1);
		}

	}

	public synchronized T getWithFK(long uid, Object... keys) {
		try {
			Tuple2<String, String> ktp = getKeys(uid, keys);
			String pk = ktp._1;
			String sk = ktp._2;
			TreeMap<String, T> cl = db.get(pk);
			if (cl != null)
				return cl.get(sk);
			return null;
		} catch (Exception e) {
			logger.error("Failed to get " + Arrays.toString(keys), e);
			return null;
		}
	}

	private String addOne(String key) {
		char[] chars = key.toCharArray();
		chars[chars.length - 1] += 1;
		return new String(chars, 0, chars.length);
	}

	public synchronized Collection<T> getWithPK(long uid, Object... keys) {
		try {
			Tuple2<String, String> ktp = getKeys(uid, keys);
			String pk = ktp._1;
			String sk = ktp._2;
			String sk_end = addOne(sk);
			TreeMap<String, T> cl = db.get(pk);
			if (cl != null) {
				return cl.subMap(sk, sk_end).values();
			}
			return null;
		} catch (Exception e) {
			logger.error("Failed to get " + Arrays.toString(keys), e);
			return null;
		}
	}

	@Override
	public boolean del(long uid, Object... keys) {
		try {
			Tuple2<String, String> ktp = getKeys(uid, keys);
			String pk = ktp._1;
			String sk = ktp._2;
			TreeMap<String, T> cl = db.get(pk);
			if (cl != null)
				cl.remove(sk);
			if (cl.isEmpty())
				db.remove(pk);
			counts.computeIfPresent(uid, (k, v) -> v - 1);
			if (counts.get(uid) < 1)
				counts.remove(uid);
			return true;
		} catch (Exception e) {
			logger.error("Failed to delete " + Arrays.toString(keys), e);
			return false;
		}
	}

	@Override
	public boolean addToCollection(long uid, String collectionName, Object value, Object... fullKey) {
		T obj = getWithFK(uid, fullKey);
		if (obj == null)
			return false;
		try {
			@SuppressWarnings("unchecked")
			Collection<Object> val = (Collection<Object>) clazz.getField(collectionName).get(obj);
			val.add(value);
			return true;
		} catch (Exception e) {
			logger.error("Failed to add val to collection.");
			return false;
		}
	}

	@Override
	public long count(long uid) {
		Long val = counts.get(uid);
		if (val != null)
			return val;
		return 0;
	}

	@Override
	public boolean check(long uid, Object... fullKey) {
		if (getWithFK(uid, fullKey) != null)
			return true;
		return false;
	}

	@Override
	public T querySingle(long rid, Object... keys) {
		return getWithFK(rid, keys);
	}

	@Override
	public T querySingleBaisc(long rid, Object... keys) {
		return querySingle(rid, keys);
	}

	@Override
	public JavaRDD<T> queryMultiple(long rid, Object... keys) {
		return this.spark.getContext().parallelize(new ArrayList<>(getWithPK(rid, keys)));
	}

	@Override
	public JavaRDD<T> queryMultipleBaisc(long rid, Object... keys) {
		return queryMultiple(rid, keys);
	}

	@Override
	public JavaRDD<T> queryMultiple(long rid, Map<String, ? extends Object> keys) {
		ArrayList<Object> params = new ArrayList<>();
		for (FieldInformation pk : primaryKeys)
			params.add(keys.get(pk.name));
		for (FieldInformation sk : secondaryKey)
			if (keys.containsKey(sk.name))
				params.add(keys.get(sk.name));
			else
				break;
		return queryMultiple(rid, params.toArray());
	}

	@Override
	public JavaRDD<T> queryMultipleBaisc(long rid, Map<String, ? extends Object> keys) {
		return queryMultiple(rid, keys);
	}

	@Override
	public JavaRDD<T> queryMultiple(long rid, String fieldName, Collection<? extends Object> keys) {
		// assume 'fieldName' is the first of the secondary key.
		return this.spark.getContext()
				.parallelize(keys.stream().map(key -> querySingle(rid, key)).collect(Collectors.toList()));
	}

	@Override
	public JavaRDD<T> queryMultipleBaisc(long rid, String fieldName, Collection<? extends Object> keys) {
		return queryMultiple(rid, keys);
	}

	@Override
	public Iterable<T> browse() {
		return Iterables.concat(Iterables.transform(db.values(), ite -> ite.values()));
	}

	@Override
	public void dump() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterable<T> browse(long rid) {
		Tuple2<String, String> tp = getKeys(rid);
		return db.get(tp._1) == null ? new ArrayList<>() : db.get(tp._1).values();
	}

	@Override
	public void prioritize() {
		this.spark.poolPrioritize();
	}

	private static class TestClass implements Serializable {

		private static final long serialVersionUID = 2531941452980897471L;

		public TestClass(int k1, int k2) {
			this.k1 = k1;
			this.k2 = k2;
			this.v1 = k1 + "-v1";
			this.v2 = k2 + "-v2";
		}

		@KeyedSecondary(index = 0)
		public Integer k1;

		@KeyedSecondary(index = 1)
		public Integer k2;

		public String v1;
		public String v2;

		@Override
		public String toString() {
			return k1 + "-" + k2 + "-" + v1 + "-" + v2;
		}
	}

	public static void main(String[] args) throws Exception {
		Environment.init(KamMode.cli);
		SparkInstance spark = SparkInstance.createLocalInstance();
		spark.init();
		ObjectFactoryRAM<TestClass> factory = new ObjectFactoryRAM<>(spark);
		factory.init("test", "test_app", TestClass.class);
		factory.put(1l, new TestClass(1, 2));
		factory.put(1l, new TestClass(2, 1));
		factory.put(1l, new TestClass(2, 2));
		System.out.println("Single Query");
		System.out.println(factory.querySingle(1, 1, 2));
		System.out.println("Range Query");
		System.out.println(factory.queryMultiple(1, 2).collect());

		System.out.println("Browse");
		factory.browse(1l).forEach(System.out::println);
		spark.close();
		factory.close();
	}

}
