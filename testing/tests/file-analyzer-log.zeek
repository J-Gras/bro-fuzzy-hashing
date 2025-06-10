# @TEST-DOC: Test adding fuzzy hashes to files.log
#
# @TEST-EXEC: ZEEKPATH=$ZEEKPATH:$PACKAGE zeek -Cr $TRACES/http-get.pcap %INPUT
# @TEST-EXEC: btest-diff files.log

@load fuzzy-hash-all-files
