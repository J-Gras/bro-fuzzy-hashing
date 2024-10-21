# @TEST-EXEC: bro -r $TRACES/http-get.pcap %INPUT > output
# TEST-EXEC: cat reporter.log >> output
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
