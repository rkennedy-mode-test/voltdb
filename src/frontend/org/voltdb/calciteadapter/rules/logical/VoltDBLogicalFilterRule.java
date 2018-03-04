/* This file is part of VoltDB.
 * Copyright (C) 2008-2017 VoltDB Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with VoltDB.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.voltdb.calciteadapter.rules.logical;

import org.apache.calcite.plan.Convention;
import org.apache.calcite.plan.RelOptRule;
import org.apache.calcite.plan.RelOptRuleCall;
import org.apache.calcite.plan.RelTraitSet;
import org.apache.calcite.rel.RelNode;
import org.apache.calcite.rel.logical.LogicalFilter;
import org.voltdb.calciteadapter.rel.logical.VoltDBLogicalFilter;
import org.voltdb.calciteadapter.rel.logical.VoltDBLogicalRel;

public class VoltDBLogicalFilterRule extends RelOptRule {

        public static final VoltDBLogicalFilterRule INSTANCE = new VoltDBLogicalFilterRule();

        VoltDBLogicalFilterRule() {
            super(operand(LogicalFilter.class, Convention.NONE, any()));
        }

        @Override
        public void onMatch(RelOptRuleCall call) {
            LogicalFilter filter = (LogicalFilter) call.rel(0);
            RelNode input = filter.getInput();
            RelTraitSet convertedTraits = filter.getTraitSet().plus(VoltDBLogicalRel.VOLTDB_LOGICAL);
            RelNode convertedInput = convert(input, input.getTraitSet().plus(VoltDBLogicalRel.VOLTDB_LOGICAL));
            call.transformTo(new VoltDBLogicalFilter(
                    filter.getCluster(),
                    convertedTraits,
                    convertedInput,
                    filter.getCondition()));
        }
}