
# JGras::FuzzyHashing

This plugin aims at integrating fuzzy hashing into Zeek and is under development. Currently the following algorithms are supported:
 * [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html)
 * [TLSH](https://github.com/trendmicro/tlsh)

## Installation

The Plugin is based on libraries for *ssdeep (libfuzzy)* and *TLSH*. Make sure to install both libraries before installing the plugin.

### Zeek Package Manager

The plugin is available as package for the [Zeek Package Manager](https://github.com/zeek/package-manager) and can be installed using the following command:

	zkg install https://github.com/J-Gras/zeek-fuzzy-hashing

### Manual Install

The following will compile and install the Fuzzy Hashing plugin alongside Zeek, assuming it can find the required libraries in a standard location:

	# ./configure && cmake --build build && 

If the headers are installed somewhere non-standard, you can point `configure` to the proper location passing the following options:

	--with-ssdeep=<ssdeep-include-directory>
	--with-tlsh=<tlsh-include-directory>

If everything built and installed correctly, you should see this:

	# zeek -NN JGras::FuzzyHashing
	JGras::FuzzyHashing - Fuzzy hashing support for Zeek (dynamic, version 0.3)
	[File Analyzer] SSDeep (ANALYZER_SSDEEP)
	[File Analyzer] TLSH (ANALYZER_TLSH)
	[Event] file_fuzzy_hash
	[Function] ssdeep_hash_init
	[Function] ssdeep_hash_update
	[Function] ssdeep_hash_finish
	[Function] tlsh_hash_init
	[Function] tlsh_hash_update
	[Function] tlsh_hash_finish

## Usage

The plugin provides opaque values for each algorithm as well as file analyzers, following standard Zeek conventions. For examples see the test cases in `tests/scripts`.
