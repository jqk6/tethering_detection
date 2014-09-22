#/bin/bash

# perl gen_trace.sim.pl sim.i30.a30.w40.s1 1 0.2 60000 2; perl detect_features.sim.pl sim.i30.a30.w40.s1.dup1.host0.2.bt60000.s2; perl statistics.sim.pl sim.i30.a30.w40.s1.dup1.host0.2.bt60000.s2


perl detect_prob.sim.pl sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s2 sim.i30.a30.w40.s1.dup1.host0.2.bt2400.s1

perl detect_prob.sim.pl sim.i30.a30.w40.s1.dup1.host0.2.bt60000.s2 sim.i30.a30.w40.s1.dup1.host0.2.bt60000.s2