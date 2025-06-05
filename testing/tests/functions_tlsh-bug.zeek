# @TEST-DOC: Test basic hash functions with workaround for TLSH bug
#
# @TEST-EXEC: cp $FILES/CHANGES.bro-aux.txt .
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

type Line: record {
	data: string;
};

global ssdeep_handle: opaque of ssdeep;
global tlsh_handle: opaque of tlsh;

# Buffer to workaround 
global tlsh_buf = "";
global tlsh_acc = T;

event read_event(description: Input::EventDescription, t: Input::Event, line: string) {
	ssdeep_hash_update(ssdeep_handle, fmt("%s\n", line));
	
	tlsh_buf += fmt("%s\n", line);
	if ( tlsh_acc && |tlsh_buf| < 50 )
		# Keep accumulating inital buffer
		return;
	else
		tlsh_acc = F;

	tlsh_hash_update(tlsh_handle, tlsh_buf);
	tlsh_buf = "";
}

event zeek_init()
	{
	ssdeep_handle = ssdeep_hash_init();
	tlsh_handle = tlsh_hash_init();

	Input::add_event([$source="CHANGES.bro-aux.txt",
		$reader=Input::READER_RAW,
		$mode=Input::MANUAL,
		$name="test",
		$fields=Line,
		$want_record=F,
		$ev=read_event]);
	}

event Input::end_of_data(name: string, source:string)
	{
	if ( name != "test" )
		return;

	local ssdeep_hash = ssdeep_hash_finish(ssdeep_handle);
	print fmt("ssdeep = %s", ssdeep_hash);

	local tlsh_hash = tlsh_hash_finish(tlsh_handle);
	print fmt("tlsh   = %s", tlsh_hash);
	}
