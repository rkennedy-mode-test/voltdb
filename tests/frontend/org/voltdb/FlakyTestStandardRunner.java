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

package org.voltdb;

import org.voltdb.FlakyTestRule.FlakyTestRunner;

/**
 * Class used (by default and, for now at least, always) to determine whether
 * or not a particular @Flaky test (that is, a JUnit test with an @Flaky
 * annotation) should be run, based on the value of the '-Drun.flaky.tests=...'
 * system variable, as well as the value of its 'isFlaky' parameter.
 */
public class FlakyTestStandardRunner implements FlakyTestRunner {

    private static String run_flaky_tests = null;
    private static Boolean debug = null;

    private static String runFlakyTests() {
        // Just once, get the value (if any) of the '-Drun.flaky.tests=...'
        // system property, specified on the command line
        if (run_flaky_tests == null) {
            run_flaky_tests = System.getProperty("run.flaky.tests", "DEFAULT");
        }
        return run_flaky_tests;
    }

    public static boolean debug() {
        // Just once, get the value (if any) of the '-Drun.flaky.tests.debug=...'
        // system property, specified on the command line
        if (debug == null) {
            debug = "TRUE".equalsIgnoreCase(System.getProperty("run.flaky.tests.debug", "FALSE"));
        }
        return debug;
    }

    /**
     * Determine whether or not this particular @Flaky test (that is, a JUnit
     * test with an @Flaky annotation) should be run, based on the value of
     * the '-Drun.flaky.tests=...' system variable, as well as the value of
     * its 'isFlaky' parameter.
     * @param testIsFlaky boolean: the value of the current test's @Flaky
     * annotation's 'isFlaky' parameter
     */
    public boolean runFlakyTest(boolean testIsFlaky) {
        return runFlakyTest(testIsFlaky, null);
    }

    /**
     * Determine whether or not this particular @Flaky test (that is, a JUnit
     * test with an @Flaky annotation) should be run, based on the value of
     * the '-Drun.flaky.tests=...' system variable, as well as the value of
     * its 'isFlaky' parameter.
     * @param testIsFlaky boolean: the value of the current test's @Flaky
     * annotation's 'isFlaky' parameter
     * @param description String: the value of the current test's @Flaky
     * annotation's 'description' parameter
     */
    public boolean runFlakyTest(boolean testIsFlaky, String description) {

        // Optional debug print
        if (debug()) {
            System.out.println("DEBUG: run.flaky.tests.debug: "+debug());
            System.out.println("DEBUG: run.flaky.tests: "+runFlakyTests());
            System.out.println("DEBUG: testIsFlaky    : "+testIsFlaky);
            System.out.println("DEBUG: description    : "+description);
        }

        // When '-Drun.flaky.tests=FALSE' (or ='false', case insensitive),
        // run only those @Flaky tests that have been marked not (or no longer)
        // @Flaky, e.g., '@Flaky(isFlaky = false)'
        if ("FALSE".equalsIgnoreCase(runFlakyTests())) {
            if (debug()) {
                System.out.println("DEBUG: test will run: "+!testIsFlaky);
            }
            return !testIsFlaky;

        // When '-Drun.flaky.tests=NONE' (or 'none', case insensitive), don't
        // run any @Flaky test, not even if it has been marked as not (or no
        // longer) @Flaky, e.g., '@Flaky(isFlaky = false)'
        } else if ("NONE".equalsIgnoreCase(runFlakyTests())) {
            if (debug()) {
                System.out.println("DEBUG: test will NOT be run!");
            }
            return false;

        // By default, including when '-Drun.flaky.tests=TRUE' (or 'true',
        // or 'ALL', or 'DEFAULT', or anything else), run all @Flaky tests
        } else {
            if (debug()) {
                System.out.println("DEBUG: test WILL be run!");
            }
            return true;
        }
    }
}
