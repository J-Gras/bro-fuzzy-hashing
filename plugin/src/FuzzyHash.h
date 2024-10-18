// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include <zeek/Val.h>
#include <zeek/file_analysis/Analyzer.h>
#include <zeek/file_analysis/File.h>

#include "FuzzyHashVal.h"
#include "events.bif.h"

namespace plugin::JGras_FuzzyHashing {

/**
 * An analyzer to produce a hash of file contents.
 */
class FuzzyHash : public zeek::file_analysis::Analyzer {
public:

	/**
	 * Destructor.
	 */
	virtual ~FuzzyHash();

	/**
	 * Incrementally hash next chunk of file contents.
	 * @param data pointer to start of a chunk of a file data.
	 * @param len number of bytes in the data chunk.
	 * @return false if the digest is in an invalid state, else true.
	 */
	virtual bool DeliverStream(const u_char* data, uint64_t len);

	/**
	 * Finalizes the hash and raises a "file_hash" event.
	 * @return always false so analyze will be deteched from file.
	 */
	virtual bool EndOfFile();

	/**
	 * Missing data can be ignored due to the nature of fuzzy hashing. Depending
	 * on the underlying algorithm, the information about how many data has been
	 * skipped might be used to improve the accuracy of the hash.
	 * @param offset byte offset in file at which missing chunk starts.
	 * @param len number of missing bytes.
	 * @return always true so the analyzer will ignore missing data.
	 */
	virtual bool Undelivered(uint64_t offset, uint64_t len);

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param hv specific hash calculator object.
	 * @param kind human readable name of the hash algorithm to use.
	 */
	FuzzyHash(zeek::RecordValPtr args, zeek::file_analysis::File* file, FuzzyHashVal* hv, zeek::StringValPtr kind);

	/**
	 * If some file contents have been seen, finalizes the hash of them and
	 * raises the "file_fuzzy_hash" event with the results.
	 */
	void Finalize();

private:
	FuzzyHashVal* fuzzy_hash;
	bool fed;
	zeek::StringValPtr kind;
};

/**
 * An analyzer to produce context triggered piecewise hashes (CTPH) of file contents
 * using the ssdeep library.
 */
class SSDeep : public FuzzyHash {
public:

	/**
	 * Create a new instance of the ssdeep hashing file analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new ssdeep analyzer instance or a null pointer if there's no
	 *         handler for the "file_hash" event.
	 */
	static zeek::file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args, zeek::file_analysis::File* file)
		{ return file_fuzzy_hash ? new SSDeep(std::move(args), file) : nullptr; }

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 */
	SSDeep(zeek::RecordValPtr args, zeek::file_analysis::File* file)
		: FuzzyHash(std::move(args), file, new SSDeepVal(), SSDeep::kind_val)
		{}

	static zeek::StringValPtr kind_val;
};

/**
 * An analyzer to produce Trend Micro Locality Sensitive Hashes (TLSH) of file contents.
 */
class TLSH : public FuzzyHash {
public:

	/**
	 * Create a new instance of the TLSH hashing file analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new TLSH analyzer instance or a null pointer if there's no
	 *         handler for the "file_hash" event.
	 */
	static zeek::file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args, zeek::file_analysis::File* file)
		{ return file_fuzzy_hash ? new TLSH(std::move(args), file) : nullptr; }

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 */
	TLSH(zeek::RecordValPtr args, zeek::file_analysis::File* file)
		: FuzzyHash(std::move(args), file, new TLSHVal(), TLSH::kind_val)
		{}

	static zeek::StringValPtr kind_val;
};

}
