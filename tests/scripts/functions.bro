# @TEST-EXEC: cp $TRACES/CHANGES.bro-aux.txt .
# @TEST-EXEC: bro %INPUT > output
# @TEST-EXEC: btest-diff output

type Line: record {
	data: string;
};

global ssdeep_handle: opaque of ssdeep;

event read_event(description: Input::EventDescription, t: Input::Event, line: string) {
	ssdeep_hash_update(ssdeep_handle, fmt("%s\n", line));
}

event bro_init()
	{
	ssdeep_handle = ssdeep_hash_init();
	Input::add_event([$source="CHANGES.bro-aux.txt",
		$reader=Input::READER_RAW,
		$mode=Input::MANUAL,
		$name="test",
		$fields=Line,
		$want_record=F,
		$fields=Line,
		$ev=read_event]);
	}

event Input::end_of_data(name: string, source:string)
	{
	if ( name != "test" )
		return;

	local ssdeep_hash = ssdeep_hash_finish(ssdeep_handle);
	print fmt("ssdeep = %s", ssdeep_hash);
	}
