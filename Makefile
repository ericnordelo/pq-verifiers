.PHONY: all bench profile report clean test

# Full pipeline: measure -> profile -> render the HTML report.
all: bench profile report

bench:
	python3 scripts/run_bench.py

profile:
	python3 scripts/profile.py

report:
	python3 scripts/gen_report.py

test:
	snforge test

clean:
	rm -rf target snfoundry_trace crates/*/snfoundry_trace
