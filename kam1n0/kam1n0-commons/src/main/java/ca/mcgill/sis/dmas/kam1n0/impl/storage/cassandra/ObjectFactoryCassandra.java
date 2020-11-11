package ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra;

import static com.datastax.spark.connector.japi.CassandraJavaUtil.javaFunctions;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.datastax.driver.core.PreparedStatement;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.ResultSetFuture;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.querybuilder.Insert;
import com.datastax.driver.core.querybuilder.QueryBuilder;
import com.datastax.spark.connector.CassandraRowMetadata;
import com.datastax.spark.connector.japi.CassandraRow;
import com.datastax.spark.connector.japi.rdd.CassandraJavaRDD;
import com.datastax.spark.connector.japi.rdd.CassandraTableScanJavaRDD;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import scala.Tuple2;
import scala.Tuple3;
import shade.com.datastax.spark.connector.google.common.util.concurrent.FutureCallback;
import shade.com.datastax.spark.connector.google.common.util.concurrent.Futures;
import shade.com.datastax.spark.connector.google.common.util.concurrent.MoreExecutors;

public class ObjectFactoryCassandra<T extends Serializable> extends ObjectFactoryMultiTenancy<T>
		implements Serializable {

	private static final long serialVersionUID = -2413690569961109428L;
	private static Logger logger = LoggerFactory.getLogger(ObjectFactoryCassandra.class);
	private transient CassandraInstance cassandra = null;
	private transient SparkInstance spark = null;
	private int binSize = 1000;

	public ObjectFactoryCassandra(CassandraInstance cassandra, SparkInstance spark) {
		String binSizeStr = System.getProperty("kam1n0.factory.cassandra.client.binsize", "500");
		binSize = Integer.parseInt(binSizeStr);
		this.cassandra = cassandra;
		this.spark = spark;
	}

	private String name_cl_meta;

	private T map(CassandraRow row) throws Exception {
		T ins = clazz.newInstance();
		for (FieldInformation info : allAttributes.values())
			if (row.contains(info.name.toLowerCase())) {
				Field field = clazz.getField(info.name);
				if (info.asByte) {
					Object val = row.getObject(info.name.toLowerCase());
					if (val instanceof ByteBuffer)
						val = ((ByteBuffer) val).array();
					field.set(ins, DmasByteOperation.convertFromBytes((byte[]) val));
				} else if (info.asString) {
					Object val = row.getObject(info.name.toLowerCase());
					field.set(ins, mapper.readValue((String) val, field.getType()));
				} else if (info.isSet) {
					Set<? extends Object> val = row.getSet(info.name.toLowerCase());
					if (info.innerAsString) {
						Class<?> pType = (Class<?>) ((ParameterizedType) field.getGenericType())
								.getActualTypeArguments()[0];
						val = val.stream().map(str -> {
							try {
								return mapper.readValue((String) str, pType);
							} catch (Exception e) {
								logger.error("Failed to deserialize subfiled {} to {}", str, pType.getName());
								return null;
							}
						}).collect(Collectors.toSet());
					}
					field.set(ins, val);
				} else if (info.isList) {
					List<? extends Object> val = row.getList(info.name.toLowerCase());
					if (info.innerAsString) {
						Class<?> pType = (Class<?>) ((ParameterizedType) field.getGenericType())
								.getActualTypeArguments()[0];
						val = val.stream().map(str -> {
							try {
								return mapper.readValue((String) str, pType);
							} catch (Exception e) {
								logger.error("Failed to deserialize subfiled {} to {}", str, pType.getName());
								return null;
							}
						}).collect(Collectors.toList());
					}
					field.set(ins, val);
				} else {
					Object val = row.getObject(info.name.toLowerCase());
					if (val instanceof ByteBuffer)
						val = ((ByteBuffer) val).array();
					field.set(ins, val);
				}
			}
		return ins;
	}

	public String getSecKeyDefinition() {
		return StringResources.JOINER_TOKEN_CSV_SPACE
				.join(secondaryKey.stream().map(key -> key.name).collect(Collectors.toList()));
	}

	public String getKeyDefinition() {
		String prefix = " PRIMARY KEY ((" + primaryKey_rid;

		String user_defs = StringResources.JOINER_TOKEN_CSV_SPACE
				.join(primaryKeys.stream().map(key -> key.name).collect(Collectors.toList()));
		if (user_defs.trim().length() > 0)
			prefix = prefix + ", " + user_defs;
		prefix = prefix + ")";

		String user_defs_sec = getSecKeyDefinition();
		if (user_defs_sec.trim().length() > 0)
			prefix = prefix + ", " + user_defs_sec;
		prefix = prefix + ")";
		return prefix;
	}

	@Override
	public void initChild() throws Exception {

		this.name_cl = app + "_" + clazz.getSimpleName().toLowerCase();
		// check or create data table
		if (!cassandra.checkColumnFamilies(spark.getConf(), name_db, name_cl)) {
			logger.info("Creating table {} {}", name_db, name_cl);
			cassandra.doWithSession(spark.getConf(), session -> {
				session.execute("CREATE KEYSPACE if not exists " + name_db + " WITH "
						+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
						+ " AND durable_writes = true;");
				// setup attributes
				List<String> attr_defs = new ArrayList<>();
				attr_defs.add(primaryKey_rid + " bigint");
				attr_defs.addAll(allAttributes.values().stream().map(tp3 -> tp3.name + " " + tp3.type)
						.collect(Collectors.toList()));
				String attr_defs_str = StringResources.JOINER_TOKEN_CSV_SPACE.join(attr_defs);
				// setup keys
				String key_defs = getKeyDefinition();
				// create table (CF)

				// TODO: is that enough to check for spark.localMode if we want to know if Cassandra is on a single
				// cluster?
				String tombstoneManagement = "";
				if (spark.localMode) {
					tombstoneManagement = "WITH COMPACTION = {'class': 'SizeTieredCompactionStrategy', 'unchecked_tombstone_compaction' : 'true'} " +
							"AND gc_grace_seconds = 0";
				}

				String query = "create table if not exists " + name_db + "." + name_cl + " (" + attr_defs_str + ","
						+ key_defs + ") " + tombstoneManagement + ";";
				logger.info("Issuing query {}", query);
				session.execute(query);
			});
		} else {
			logger.info("Found column family: {}.{}", name_db, name_cl);
		}

		// helpers for query:
		queryConditions = new ArrayList<>();
		queryConditions.add(primaryKey_rid + " = ?");
		queryConditions.addAll(primaryKeys.stream().map(info -> info.name + " = ?").collect(Collectors.toList()));
		queryConditions.addAll(secondaryKey.stream().map(info -> info.name + " = ?").collect(Collectors.toList()));

		// meta data:
		this.name_cl_meta = name_cl + "_meta";
		if (!cassandra.checkColumnFamilies(spark.getConf(), name_db, name_cl_meta)) {
			logger.info("Creating table {} {}", name_db, name_cl_meta);
			cassandra.doWithSession(spark.getConf(), session -> {
				session.execute("CREATE KEYSPACE if not exists " + name_db + " WITH "
						+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
						+ " AND durable_writes = true;");
				String query = "create table if not exists " + name_db + "." + name_cl_meta
						+ " ( rid bigint primary key, counts counter );";
				logger.info("Issuing query {}", query);
				session.execute(query);
			});
		} else {
			logger.info("Found column family: {}.{}", name_db, name_cl_meta);
		}
	}

	@Override
	public void close() {
	}

	@Override
	public void put(long rid, T obj, boolean async) {
		this.update(rid, obj, async, true);
	}

	@Override
	public void update(long rid, T obj, boolean async) {
		this.update(rid, obj, async, false);
	}

	@SuppressWarnings("unchecked")
	public void update(long rid, T obj, boolean async, boolean addC) {
		cassandra.doWithSession(sess -> {
			Insert query = QueryBuilder.insertInto(name_db, name_cl);
			query.value(primaryKey_rid, rid);
			for (FieldInformation info : allAttributes.values())
				try {
					Object val = clazz.getField(info.name).get(obj);

					if (info.asByte)
						val = ByteBuffer.wrap(DmasByteOperation.convertToBytes(val));
					else if (info.asString)
						val = mapper.writeValueAsString(val);
					else if (val instanceof byte[])
						val = ByteBuffer.wrap((byte[]) val);
					else if (info.isCollection() && info.innerAsString) {
						Collection<? extends Object> clt = (Collection<? extends Object>) val;
						if (clt == null && val != null)
							logger.error(
									"The supplied value is not collection but the field is defined as is. "
											+ "Failed to process record {}. Inserted as it is.",
									val.getClass().getName());
						Stream<String> stream = clt.stream().map(clo -> {
							try {
								return mapper.writeValueAsString(clo);
							} catch (JsonProcessingException e) {
								logger.error("Failed to write object as string. Class:" + clo.getClass().getName());
								return null;
							}
						}).filter(clo -> clo != null);
						if (info.isList)
							val = stream.collect(Collectors.toCollection(ArrayList::new));
						else
							val = stream.collect(Collectors.toCollection(HashSet::new));
					}
					query.value(info.name, val);
				} catch (Exception e) {
					logger.error("Failed to set field " + info + "with value", e);
				}
			if (async) {
				ResultSetFuture future = sess.executeAsync(query);
				Futures.addCallback(future, new FutureCallback<ResultSet>() {
					@Override
					public void onSuccess(ResultSet result) {
					}

					@Override
					public void onFailure(Throwable t) {
						logger.error("Failed to put value.", t);
					}
				}, MoreExecutors.directExecutor());
			} else {
				sess.execute(query);
			}
			if (addC) {
				PreparedStatement inc_stm = sess
						.prepare("UPDATE " + name_db + "." + name_cl_meta + " SET counts = counts + 1 WHERE rid = ?");
				sess.executeAsync(inc_stm.bind(rid));
			}
		});
	}

	private JavaRDD<T> get(long rid, String[] fields, Object... keys) {
		String conditions = StringResources.JOINER_TOKEN_ANDC_SPACE.join(queryConditions.subList(0, keys.length + 1));
		Object[] nkeys = new Object[keys.length + 1];
		nkeys[0] = rid;
		for (int i = 0; i < keys.length; ++i)
			nkeys[i + 1] = keys[i];
		CassandraTableScanJavaRDD<CassandraRow> tbl = javaFunctions(spark.getContext()).cassandraTable(name_db,
				name_cl);
		if (fields != null)
			tbl = tbl.select(fields);
		return tbl.where(conditions, nkeys).map(this::map);
	}

	private JavaRDD<T> get(long rid, String[] fields, Map<String, ? extends Object> keyMap) {
		String conditions = StringResources.JOINER_TOKEN_ANDC_SPACE
				.join(keyMap.entrySet().stream().map(ent -> ent.getKey() + " = ?").collect(Collectors.toList()));
		conditions = primaryKey_rid + " = ? AND " + conditions;
		Object[] keys = keyMap.entrySet().stream().map(ent -> ent.getValue()).toArray();
		Object[] nkeys = new Object[keys.length + 1];
		nkeys[0] = rid;
		for (int i = 0; i < keys.length; ++i)
			nkeys[i + 1] = keys[i];
		CassandraTableScanJavaRDD<CassandraRow> tbl = javaFunctions(spark.getContext()).cassandraTable(name_db,
				name_cl);
		if (fields != null)
			tbl = tbl.select(fields);
		return tbl.where(conditions, nkeys).map(this::map);
	}

	@Override
	public T querySingle(long rid, Object... keys) {
		if (keys.length != queryConditions.size() - 1) {
			logger.error("The object class {} expects {} keys. Only {}+1 are given.", clazz.getName(), queryConditions,
					keys.length);
			return null;
		}
		List<T> val = get(rid, null, keys).collect();
		if (val.size() != 0)
			return val.get(0);
		return null;
	}

	@Override
	public T querySingleBaisc(long rid, Object... keys) {
		if (keys.length != queryConditions.size() - 1) {
			logger.error("The object class {} expects {} keys. Only {}+1 are given.", clazz.getName(), queryConditions,
					keys.length);
			return null;
		}
		List<T> val = get(rid, null, keys).collect();
		if (val.size() != 0)
			return val.get(0);
		return null;
	}

	@Override
	public JavaRDD<T> queryMultiple(long rid, Object... keys) {
		if (keys.length > queryConditions.size() - 1) {
			logger.error("Invalid number of arguments. Max {}-1 expected but {} given.", queryConditions.size(),
					keys.length);
		}
		return get(rid, null, keys);
	}

	@Override
	public JavaRDD<T> queryMultipleBaisc(long rid, Object... keys) {
		if (keys.length > queryConditions.size() - 1) {
			logger.error("Invalid number of arguments. Max {}-1 expected but {} given.", queryConditions.size(),
					keys.length);
		}
		return get(rid, basicAttributes, keys);
	}

	@Override
	public JavaRDD<T> queryMultiple(long rid, Map<String, ? extends Object> keys) {
		return get(rid, null, keys);
	}

	@Override
	public JavaRDD<T> queryMultipleBaisc(long rid, Map<String, ? extends Object> keys) {
		return get(rid, basicAttributes, keys);
	}

	@Override
	public JavaRDD<T> queryMultiple(long rid, String fieldName, Collection<? extends Object> keys) {
		List<List<Object>> partitions = new ArrayList<>();
		partitions.add(new ArrayList<Object>());
		int c = 0;
		for (Object sid : keys) {
			if (++c % binSize == 0)
				partitions.add(new ArrayList<Object>());
			partitions.get(partitions.size() - 1).add(sid);
		}
		List<JavaRDD<T>> sblks = partitions.parallelStream()
				.map(par -> javaFunctions(spark.getContext()).cassandraTable(name_db, name_cl)
						.where(primaryKey_rid + " = ? AND " + fieldName + " in ?", rid, par).map(this::map))
				.collect(Collectors.toList());
		JavaRDD<T> sblk = sblks.get(0);
		if (sblks.size() > 1)
			sblk = spark.getContext().union(sblk, sblks.subList(1, sblks.size()));
		return sblk;
	}

	@Override
	public JavaRDD<T> queryMultipleBaisc(long rid, String fieldName, Collection<? extends Object> keys) {
		List<List<Object>> partitions = new ArrayList<>();
		partitions.add(new ArrayList<Object>());
		int c = 0;
		for (Object sid : keys) {
			if (++c % binSize == 0)
				partitions.add(new ArrayList<Object>());
			partitions.get(partitions.size() - 1).add(sid);
		}

		List<JavaRDD<T>> sblks = partitions.parallelStream()
				.map(par -> javaFunctions(spark.getContext()).cassandraTable(name_db, name_cl).select(basicAttributes)
						.where(primaryKey_rid + " = ? AND " + fieldName + " in ?", rid, par).map(this::map))
				.collect(Collectors.toList());
		JavaRDD<T> sblk = sblks.get(0);
		if (sblks.size() > 1)
			sblk = spark.getContext().union(sblk, sblks.subList(1, sblks.size()));
		return sblk;
	}

	@Override
	public boolean del(long rid, Object... keys) {
		if (keys.length < 0 || keys.length > queryConditions.size() - 1) {
			logger.error("Invalid number of arguments. Max {}-1 expected but {} given.", queryConditions.size(),
					keys.length);
			return false;
		}
		cassandra.doWithSession(sess -> {
			String conditions = StringResources.JOINER_TOKEN_ANDC_SPACE
					.join(queryConditions.subList(0, keys.length + 1));
			PreparedStatement cmt_statement = sess
					.prepare("DELETE FROM " + name_db + "." + name_cl + " where " + conditions);
			Object[] nkeys = new Object[keys.length + 1];
			nkeys[0] = rid;
			for (int i = 0; i < keys.length; ++i)
				nkeys[i + 1] = keys[i];
			sess.executeAsync(cmt_statement.bind(nkeys));

			PreparedStatement dec_stm = sess
					.prepare("UPDATE " + name_db + "." + name_cl_meta + " SET counts = counts + -1 WHERE rid = ?");
			sess.executeAsync(dec_stm.bind(rid));
		});
		return true;
	}

	@Override
	public boolean addToCollection(long rid, String collectionName, Object value, Object... fullKey) {
		if (fullKey.length != queryConditions.size() - 1) {
			logger.error("The object class {} expects {} keys. Only {}+1 are given.", clazz.getName(), queryConditions,
					fullKey.length);
			return false;
		}
		String cn = collectionName.toLowerCase();
		if (!collectionAttributes.contains(cn)) {
			logger.error("{} not defined as a collection attribute in {}.", cn, collectionAttributes);
			return false;
		}
		cassandra.doWithSession(sess -> {
			String conditions = StringResources.JOINER_TOKEN_ANDC_SPACE.join(queryConditions);
			PreparedStatement cmt_statement = sess.prepare(
					"UPDATE " + name_db + "." + name_cl + " SET " + cn + " = " + cn + " + ? WHERE " + conditions);
			FieldInformation info = allAttributes.get(collectionName);
			Object[] params = new Object[fullKey.length + 2];
			if (info.innerAsString)
				try {
					params[0] = mapper.writeValueAsString(value);
				} catch (Exception e) {
					logger.error("Failed to write object as json. Class:" + value.getClass().getName(), e);
					params[0] = value;
				}
			else
				params[0] = value;
			if (info.isList)
				params[0] = Arrays.asList(params[0]);
			else
				params[0] = Sets.newHashSet(params[0]);
			params[1] = rid;
			for (int i = 0; i < fullKey.length; ++i)
				params[i + 2] = fullKey[i];
			logger.info(cmt_statement.getQueryString());
			logger.info(Arrays.toString(params));
			sess.execute(cmt_statement.bind(params));
		});
		return true;
	}

	@Override
	public Iterable<T> browse() {
		JavaSparkContext sc = spark.getContext();
		CassandraJavaRDD<CassandraRow> rdd2 = javaFunctions(sc).cassandraTable(name_db, name_cl);
		return rdd2.map(row -> map(row)).collect();
	}

	@Override
	public Iterable<T> browse(long rid) {
		return get(rid, null).collect();
	}

	@Override
	public long count(long rid) {
		Row row = cassandra.doWithSessionWithReturn(sess -> {
			PreparedStatement cmt_statement = sess
					.prepare("SELECT counts FROM " + name_db + "." + name_cl_meta + " WHERE rid = ?");
			return sess.execute(cmt_statement.bind(rid)).one();
		});
		if (row == null || row.isNull(0))
			return 0;
		return row.getLong(0);
	}

	@Override
	public boolean check(long rid, Object... keys) {
		if (keys.length < 1 || keys.length > queryConditions.size() - 1) {
			logger.error("Invalid number of arguments. Max {}-1 expected but {} given.", queryConditions.size(),
					keys.length);
			return false;
		}
		return cassandra.doWithSessionWithReturn(sess -> {
			String conditions = StringResources.JOINER_TOKEN_ANDC_SPACE
					.join(queryConditions.subList(0, keys.length + 1));
			PreparedStatement stm = sess
					.prepare("SELECT count(*) FROM " + name_db + "." + name_cl + " WHERE " + conditions);
			Object[] nkeys = new Object[keys.length + 1];
			nkeys[0] = rid;
			for (int i = 0; i < keys.length; ++i)
				nkeys[i + 1] = keys[i];
			return (Long) (sess.execute(stm.bind(nkeys)).one().getObject(0)) > 0;
		});
	}

	@Override
	public void prioritize() {
		this.spark.poolPrioritize();
	};

	public static class TestClass implements Serializable {
		private static final long serialVersionUID = 5555318185697863451L;

		public static class TestClassSub implements Serializable {
			private static final long serialVersionUID = 3161318088139133552L;
			public String val = "";

			public TestClassSub() {
			}

			public TestClassSub(String val) {
				this.val = val;
			}
		}

		public TestClass() {
		}

		@KeyedPrimary
		public long id;

		@KeyedSecondary(index = 0)
		public long sid0;

		@KeyedSecondary(index = 1)
		public long sid1;

		public String val;

		public Set<Long> all_ids = new HashSet<>();

		public List<Long> all_ids_ls = new ArrayList<>();

		public List<String> all_ids_ls_str = new ArrayList<>();

		@InnerAsString
		public List<TestClassSub> all_ids_ls_str2 = new ArrayList<>();

		public byte[] blbs;

		@AsBytes
		public Set<String> hello = Sets.newHashSet("Hello Word!");

		public TestClass(int val, int val0, int val1) {
			this.id = val;
			this.sid0 = val0;
			this.sid1 = val1;
			this.val = val + "-" + val0 + "-" + val1;
			this.all_ids.add((long) val);
			this.all_ids.add((long) val0);
			this.all_ids.add((long) val1);
			this.all_ids_ls.addAll(this.all_ids);
			this.all_ids_ls.stream().map(l -> l.toString()).forEach(this.all_ids_ls_str::add);
			this.all_ids_ls_str2 = this.all_ids_ls_str.stream().map(str -> new TestClassSub(str))
					.collect(Collectors.toList());
			blbs = DmasByteOperation.getBytes(id);
		}

		@Override
		public String toString() {
			try {
				return mapper.writeValueAsString(this);
			} catch (Exception e) {
				return super.toString();
			}
		}
	}

	@Override
	public void dump() {
		List<CassandraRow> tbl = javaFunctions(spark.getContext()).cassandraTable(name_db, name_cl).collect();
		tbl.stream().forEach(System.out::println);
	}

	public static void main(String[] args) throws Exception {

		Environment.init();

		CassandraInstance cassandra = CassandraInstance.createEmbeddedInstance("test", true, false);
		cassandra.init();
		SparkInstance spark = SparkInstance.createLocalInstance(cassandra.getSparkConfiguration());
		spark.init();
		cassandra.setSparkInstance(spark);

		ObjectFactoryCassandra<TestClass> testFactory = new ObjectFactoryCassandra<>(cassandra, spark);
		testFactory.init("dbtest", "app", TestClass.class);
		long rid = 23;
		int m = 3;
		for (int i = 0; i < m; i++)
			for (int j = 0; j < m; j++)
				for (int k = 0; k < m; k++)
					testFactory.put(rid, new TestClass(i, j, k));
		// testFactory.dump();

		IntStream.range(0, m).mapToObj(i -> i).flatMap(i -> IntStream.range(0, m).mapToObj(j -> new Tuple2<>(i, j)))
				.flatMap(tp -> IntStream.range(0, m).mapToObj(k -> new Tuple3<>(tp._1(), tp._2(), k))).parallel()
				.forEach(tp3 -> {
					logger.info(testFactory.querySingle(rid, tp3._1(), tp3._2(), tp3._3()).toString());
				});

		for (int i = 0; i < m; i++)
			for (int j = 0; j < m; j++)
				logger.info(testFactory.queryMultiple(rid, i, j).collect().toString());

		for (int i = 0; i < m; i++)
			logger.info(testFactory.queryMultiple(rid, i).collect().toString());

		for (int i = 0; i < m; i++)
			logger.info(testFactory.queryMultipleBaisc(rid, i).collect().toString());

		testFactory.addToCollection(rid, "all_ids_ls_str2", new TestClass.TestClassSub("hihihihihihihihihihihi!!!!"),
				0l, 1l, 2l);

		logger.info(testFactory.querySingle(rid, 0, 1, 2).toString());

		logger.info(testFactory.queryMultiple(rid, 0).collect().toString());

		logger.info("" + testFactory.check(rid, 0l, 1l, 2l));

		testFactory.close();
		cassandra.close();
		spark.close();
	}

}
