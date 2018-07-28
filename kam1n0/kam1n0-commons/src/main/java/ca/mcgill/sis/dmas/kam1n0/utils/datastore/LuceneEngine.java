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
package ca.mcgill.sis.dmas.kam1n0.utils.datastore;

import java.io.IOException;
import java.util.ArrayList;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopScoreDocCollector;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.RAMDirectory;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public class LuceneEngine {

	StandardAnalyzer analyzer = new StandardAnalyzer();
	Directory index = new RAMDirectory();

	IndexWriterConfig getConf() {
		return new IndexWriterConfig(analyzer);
	}

	int r = 10;
	IndexReader reader;
	IndexWriter w;
	private IndexSearcher searcher;

	public LuceneEngine(int numTopHits) {
		r = numTopHits;
		BooleanQuery.setMaxClauseCount(1024 * 32);
	}

	public void index(Function func, String batch) throws Exception {
		addFunc(w, func, batch);
	}

	public void openWriter() throws IOException {
		w = new IndexWriter(index, getConf());
	}

	public void closeWriter() throws IOException {
		if (w != null)
			w.close();
	}

	public synchronized void openReader() throws IOException {
		if (searcher == null) {
			reader = DirectoryReader.open(index);
			searcher = new IndexSearcher(reader);
		}
	}

	public void closeReader() throws IOException {
		if (reader != null)
			reader.close();
	}

	public ArrayList<EntryPair<Long, Double>> query(String query, int topK) throws Exception {
		ArrayList<EntryPair<Long, Double>> result = new ArrayList<>();
		if (query.trim().length() < 1)
			return result;
		Query q = new QueryParser("content", analyzer).parse(QueryParser.escape(query));
		TopScoreDocCollector collector = TopScoreDocCollector.create(topK);
		searcher.search(q, collector);
		ScoreDoc[] hits = collector.topDocs().scoreDocs;
		for (int i = 0; i < hits.length; ++i) {
			int docId = hits[i].doc;
			Document d = searcher.doc(docId);
			result.add(new EntryPair<Long, Double>(Long.parseLong(d.get("fid")), (double) hits[i].score));
		}
		return result;
	}

	private static void addFunc(IndexWriter w, Function func, String rep) throws IOException {
		Document doc = new Document();
		doc.add(new TextField("content", rep, Field.Store.YES));
		doc.add(new StringField("fid", Long.toString(func.functionId), Field.Store.YES));
		w.addDocument(doc);
	}
}
