# @TEST-EXEC: bro -r $TRACES/http-get-large.pcap %INPUT > output
# @TEST-EXEC: bro -r $TRACES/http-get-large-incomplete.pcap %INPUT >> output
# @TEST-EXEC: btest-diff output

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    print "new file", f$id;
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    Files::add_analyzer(f, Files::ANALYZER_SSDEEP);
    }

event file_fuzzy_hash(f: fa_file, kind: string, hash: string)
    {
    print "file_fuzzy_hash", f$id, kind, hash;
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    print "file_hash", f$id, kind, hash;
    }
