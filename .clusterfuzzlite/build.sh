
export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
# cf https://github.com/google/sanitizers/issues/1389
export MSAN_OPTIONS=strict_memcmp=false

rm /lib/x86_64-linux-gnu/libjansson.so*
rm /lib/x86_64-linux-gnu/libpcap.so*
rm /lib/x86_64-linux-gnu/libyaml.so*
rm /lib/x86_64-linux-gnu/libmagic.so*
#rm /lib/x86_64-linux-gnu/libpcre2-8.so*

#we did not put libhtp there before so that cifuzz does not remove it
#mv $SRC/libhtp ./
# build project
sh autogen.sh
#run configure with right options
if [ "$SANITIZER" = "address" ]
then
    export RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth -Ccodegen-units=1"
fi
./src/tests/fuzz/oss-fuzz-configure.sh
make -j$(nproc)

./src/suricata --list-app-layer-protos | tail -n +2 | while read i; do cp src/fuzz_applayerparserparse $OUT/fuzz_applayerparserparse_$i; done

cp src/fuzz_* $OUT/

# dictionaries
./src/suricata --list-keywords | grep "\- " | sed 's/- //' | awk '{print "\""$0"\""}' > $OUT/fuzz_siginit.dict

echo \"SMB\" > $OUT/fuzz_applayerparserparse_smb.dict

# build corpuses
# default configuration file
zip -r $OUT/fuzz_confyamlloadstring_seed_corpus.zip suricata.yaml
# rebuilds rules corpus with only one rule by file
unzip ../emerging.rules.zip
cd rules
cat *.rules > $OUT/fuzz.rules
i=0
mkdir corpus
# quiet output for commands
set +x
cat *.rules | while read l; do echo $l > corpus/$i.rule; i=$((i+1)); done
set -x
zip -q -r $OUT/fuzz_siginit_seed_corpus.zip corpus
cd ../../suricata-verify

# corpus with single files
find . -name "*.pcap" | xargs zip -r $OUT/fuzz_decodepcapfile_seed_corpus.zip
find . -name "*.yaml" | xargs zip -r $OUT/fuzz_confyamlloadstring_seed_corpus.zip
find . -name "*.rules" | xargs zip -r $OUT/fuzz_siginit_seed_corpus.zip

# corpus using both rule and pcap as in suricata-verify
cd tests
i=0
mkdir corpus
set +x
ls | grep -v corpus | while read t; do
cat $t/*.rules > corpus/$i || true; echo -ne '\0' >> corpus/$i; cat $t/*.pcap >> corpus/$i || true; i=$((i+1));
done
set -x
zip -q -r $OUT/fuzz_sigpcap_seed_corpus.zip corpus
rm -Rf corpus
mkdir corpus
set +x
ls | grep -v corpus | while read t; do
grep -v "#" $t/*.rules | head -1 | cut -d "(" -f2 | cut -d ")" -f1 > corpus/$i || true; echo -ne '\0' >> corpus/$i; fpc_bin $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
echo -ne '\0' >> corpus/$i; python3 $SRC/fuzzpcap/tcptofpc.py $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
done
set -x
zip -q -r $OUT/fuzz_sigpcap_aware_seed_corpus.zip corpus
echo "\"FPC0\"" > $OUT/fuzz_sigpcap_aware.dict
rm -Rf corpus
mkdir corpus
set +x
ls | grep -v corpus | while read t; do
fpc_bin $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
python3 $SRC/fuzzpcap/tcptofpc.py $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
done
set -x
zip -q -r $OUT/fuzz_predefpcap_aware_seed_corpus.zip corpus
echo "\"FPC0\"" > $OUT/fuzz_predefpcap_aware.dict
