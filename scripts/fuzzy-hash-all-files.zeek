## Add fuzzy hashes to files.log
module FuzzyHash;

export {
	redef record Files::Info += {
		## A SSDEEP digest of the file contents.
		ssdeep: string &log &optional;
		## A TLSH digest of the file contents.
		tlsh: string &log &optional;
	};

}

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_SSDEEP);
	Files::add_analyzer(f, Files::ANALYZER_TLSH);
	}

event file_fuzzy_hash(f: fa_file, kind: string, hash: string) &priority=5
	{
	switch ( kind ) {
	case "ssdeep":
		f$info$ssdeep = hash;
		break;
	case "tlsh":
		f$info$tlsh = hash;
		break;
	}
	}
