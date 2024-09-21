PROVERIF=proverif -html


all: trace_Payload-Integrity_Fix 	trace_Payload-Integrity_SDNSEC 	trace_Route-Integrity_Fix 	trace_Route-Integrity_SDNSEC 	trace_Accountability-Completeness_Fix  trace_Accountability-Soundness_Fix  trace_Accountability-Soundness_SDNSEC

trace_%: %.pv
	mkdir -p $@
	$(PROVERIF) $@ $^

clean:
	rm -rf trace_*
