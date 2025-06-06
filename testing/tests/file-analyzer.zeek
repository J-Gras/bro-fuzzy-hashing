# @TEST-DOC: Test fuzzy hash file analyzers
#
# @TEST-EXEC: zeek -Cr $TRACES/http-get.pcap %INPUT | sort -r > output
# @TEST-EXEC: btest-diff output

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    print "new file", f$id;
    Files::add_analyzer(f, Files::ANALYZER_SSDEEP);
    Files::add_analyzer(f, Files::ANALYZER_TLSH);
    }

event file_fuzzy_hash(f: fa_file, kind: string, hash: string)
    {
    print fmt("file_hash of %s as %s = %s", f$id, kind, hash);
    }
