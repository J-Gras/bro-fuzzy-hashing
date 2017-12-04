# @TEST-EXEC: bro -r $TRACES/http-get.pcap %INPUT > output
# TEST-EXEC: cat reporter.log >> output
# @TEST-EXEC: btest-diff output

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    print "new file", f$id;
    Files::add_analyzer(f, Files::ANALYZER_SSDEEP);
    }

event file_hash_ssdeep(f: fa_file, hash: string)
    {
    print "file_hash", f$id, hash;
    }
