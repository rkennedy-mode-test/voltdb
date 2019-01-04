/* This file is part of VoltDB.
 * Copyright (C) 2008-2019 VoltDB Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

package org.voltdb.plannerv2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;

import org.apache.calcite.sql.SqlLiteral;
import org.apache.calcite.sql.parser.SqlParseException;
import org.apache.calcite.sql.parser.SqlParserPos;
import org.apache.calcite.sql.util.SqlBasicVisitor;
import org.apache.calcite.util.Litmus;
import org.junit.Test;

public class TestQueryParameterization {

    @Test public void testParameterization() throws SqlParseException {
        ParameterizationTestCase[] testCases = {
                new ParameterizationTestCase(
                        "select * from T where id = 7 and name = 'Chao' and cnt = 566 LIMIT 2 OFFSET 3",
                        "select * from T where id = ? and name = ? and cnt = ? LIMIT ? OFFSET ?",
                        num("7"), str("Chao"), num("566"), num("2"), num("3")),
                new ParameterizationTestCase(
                        "select * from T where id = 7 and cnt < 566 and name = 'Chao'",
                        "select * from T where id = ? and cnt < ? and name = ?",
                        num("7"), num("566"), str("Chao")),
                new ParameterizationTestCase(
                        "INSERT INTO T VALUES (7, 'Chao', 566)",
                        "INSERT INTO T VALUES (?, ?, ?)",
                        num("7"), str("Chao"), num("566")),
                new ParameterizationTestCase(
                        "SELECT * FROM T WHERE cnt IN (1, 3, 5)",
                        "SELECT * FROM T WHERE cnt IN (?, ?, ?)",
                        num("1"), num("3"), num("5")),
                new ParameterizationTestCase(
                        "select name from T where id > 7 group by cnt having count(id) > 5",
                        "select name from T where id > ? group by cnt having count(id) > ?",
                        num("7"), num("5")),
                new ParameterizationTestCase(
                        "select id, rank() over(PARTITION BY cnt+1 ORDER BY name) LIMIT 2 OFFSET 3",
                        "select id, rank() over(PARTITION BY cnt+? ORDER BY name) LIMIT ? OFFSET ?",
                        num("1"), num("2"), num("3"))
        };
        for (ParameterizationTestCase testCase : testCases) {
            testCase.run();
        }
    }

    /**
     * Test the not parameterizable cases defined in
     * {@link ParameterizedSqlTask#ParameterizedSqlTask(SqlTask)}
     * @throws SqlParseException
     */
    @Test public void testNotParameterizable() throws SqlParseException {
        // Cannot parameterized a query that already got user parameters.
        ParameterizedSqlTask task = new ParameterizedSqlTask(SqlTask.from(
                "select * from T where id = 7 and cnt < ? and name = 'Chao'"));
        assertNull(task.getSqlLiteralList());

        // We do not parameterize DDL.
        task = new ParameterizedSqlTask(SqlTask.from(
                "CREATE TABLE t1 (a INT DEFAULT 1)"));
        assertNull(task.getSqlLiteralList());
    }

    /**
     * Test the queries that can still have some SqlLiterals after being parameterized.
     * They still have some preserved SqlLiterals because those SqlLiterals did not come
     * from the literal values in the user query, but are generated by the parser to
     * store some internal states.
     * @throws SqlParseException if the parsing goes wrong.
     * @see ParameterizationVisitor#visit(SqlLiteral)
     */
    @Test public void testAvoidTooAggressiveParameterization() throws SqlParseException {
        // Window aggregation query
        // The allow-partial case is not tested, but it is not supported by VoltDB yet.
        assertHasLiteralsLeft("select id, rank() over(PARTITION BY cnt+1 ORDER BY name) LIMIT 2 OFFSET 3", 1);
        // Join query
        assertHasLiteralsLeft("select T1.a from T1 JOIN T2 on T1.a = T2.a", 3);
    }

    /**
     * A helper class to test the result of parameterization.
     */
    private static class ParameterizationTestCase {
        final ParameterizedSqlTask m_actualTask;
        final SqlTask m_expectedTask;
        final List<SqlLiteral> m_expectedLiterals = new ArrayList<>();

        /**
         * Build a parameterization test case.
         * @param original the original, not parameterized query.
         * @param parameterized the parameterized answer of the original query,
         * using "?" as parameter place-holders.
         * @param literals the extracted literals for the parameters in the original query.
         * @throws SqlParseException if the parsing goes wrong.
         */
        public ParameterizationTestCase(String original,
                String parameterized, SqlLiteral... literals) throws SqlParseException {
            m_actualTask = new ParameterizedSqlTask(SqlTask.from(original));
            m_expectedTask = SqlTask.from(parameterized);
            for (SqlLiteral literal : literals) {
                m_expectedLiterals.add(literal);
            }
        }

        /**
         * Verify that the query trees of the parameterized original query and the answer query
         * are the same. Also, verify that the extracted parameter literals are correct.
         */
        public void run() {
            // Make sure that the parameterized query looks good.
            m_actualTask.getParsedQuery().equalsDeep(m_expectedTask.getParsedQuery(), Litmus.THROW);
            List<SqlLiteral> actualLiterals = m_actualTask.getSqlLiteralList();
            assertEquals(m_expectedLiterals.size(), actualLiterals.size());
            // Compare the parameter values.
            for (int i = 0; i < actualLiterals.size(); i++) {
                actualLiterals.get(i).equalsDeep(m_expectedLiterals.get(i), Litmus.THROW);
            }
        }
    }

    private SqlLiteral num(String str) {
        return SqlLiteral.createExactNumeric(str, SqlParserPos.ZERO);
    }

    private SqlLiteral str(String str) {
        return SqlLiteral.createCharString(str, SqlParserPos.ZERO);
    }

    /**
     * A visitor to count {@link SqlLiteral} in a node tree.
     * Used for testing in {@link testAvoidTooAggressiveParameterization}
     * @author Yiqun Zhang
     * @since 9.0
     */
    private static final class SqlLiteralCounter extends SqlBasicVisitor<Void> {
        private int m_count = 0;
        @Override
        public Void visit(SqlLiteral literal) {
            ++m_count;
            return null;
        }
        public int getLiteralCount() {
            return m_count;
        }
    }

    /**
     * Assert on the number of {@code SqlLiteral}s left after query parameterization.
     * @param sql the original, not parameterized query.
     * @param expectedLiteralsLeft the expected number of {@code SqlLiteral} left after parameterization.
     * @throws SqlParseException if the query parsing goes wrong.
     */
    private void assertHasLiteralsLeft(String sql, int expectedLiteralsLeft) throws SqlParseException {
        ParameterizedSqlTask task = new ParameterizedSqlTask(SqlTask.from(sql));
        SqlLiteralCounter counter = new SqlLiteralCounter();
        task.getParsedQuery().accept(counter);
        assertEquals(expectedLiteralsLeft, counter.getLiteralCount());
    }
}
