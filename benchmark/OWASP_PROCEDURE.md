# OWASP Benchmark Procedure

## Setup (one-time)
```bash
cd /tmp
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git OWASP-Benchmark
cd OWASP-Benchmark
mvn compile  # requires Java 8+ and Maven
```

## Run GSC against OWASP Benchmark
```bash
cd ~/gsc
python3 gsc.py benchmark owasp \
  --benchmark-path /tmp/OWASP-Benchmark \
  --expected-csv /tmp/OWASP-Benchmark/expectedresults-1.2.csv \
  --output benchmark/owasp_results.json
```

## Calculate TPR/FPR
```bash
python3 benchmark/scorer.py benchmark/owasp_results.json
# Expected output: TPR, FPR, precision, recall per CWE category
```

## Status
- [ ] OWASP Benchmark cloned
- [ ] Maven build
- [ ] GSC scan
- [ ] TPR/FPR calculation
- [ ] Compare with Semgrep/Snyk/CodeQL
