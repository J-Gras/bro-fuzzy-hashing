// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_PLUGIN_JGRAS_SSDEEP_ANALYZER_H
#define BRO_PLUGIN_JGRAS_SSDEEP_ANALYZER_H

#include <Val.h>
#include <file_analysis/Analyzer.h>

//extern "C" {
#include <fuzzy.h>
//}

namespace plugin {
namespace JGras_SSDeep {


/**
 * An analyzer to produce context triggered piecewise hashes (CTPH) of file contents.
 */
class SSDeep : public file_analysis::Analyzer {
public:

	/**
	 * Destructor.
	 */
	virtual ~SSDeep();

	/**
	 * Create a new instance of the ssdeep hashing file analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new ssdeep analyzer instance or a null pointer if there's no
	 *         handler for the "file_hash_ssdeep" event.
	 */
	static file_analysis::Analyzer* Instantiate(RecordVal* args, file_analysis::File* file);

	/**
	 * Incrementally hash next chunk of file contents.
	 * @param data pointer to start of a chunk of a file data.
	 * @param len number of bytes in the data chunk.
	 * @return false if the digest is in an invalid state, else true.
	 */
	virtual bool DeliverStream(const u_char* data, uint64 len);

	/**
	 * Finalizes the hash and raises a "file_hash" event.
	 * @return always false so analyze will be deteched from file.
	 */
	virtual bool EndOfFile();

	/**
	 * Missing data can't be handled, so just indicate the this analyzer should
	 * be removed from receiving further data.  The hash will not be finalized.
	 * @param offset byte offset in file at which missing chunk starts.
	 * @param len number of missing bytes.
	 * @return always false so analyzer will detach from file.
	 * TODO!
	 */
	virtual bool Undelivered(uint64 offset, uint64 len);

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param hv specific hash calculator object.
	 * @param kind human readable name of the hash algorithm to use.
	 */
	SSDeep(RecordVal* args, file_analysis::File* file);

	/**
	 * If some file contents have been seen, finalizes the hash of them and
	 * raises the "file_hash" event with the results.
	 */
	void Finalize();

private:
	//HashVal* hash;
	bool fed;
	fuzzy_state* state;
};

}
}

#endif