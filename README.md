
# JGras::FuzzyHashing

This plugin aims at integrating fuzzy hashing into Bro and is under development. Currently the following algorithms are supported:
 * [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html)
 * [TLSH](https://github.com/trendmicro/tlsh)

## Installation

The Plugin is based on libraries for `ssdeep` (libfuzzy) and `TLSH`. Make sure to install both libraries before installing the plugin.

### Bro Package Manager

The plugin is available as package for the [Bro Package Manager](https://github.com/bro/package-manager) and can be installed using the following command:

	bro-pkg install https://github.com/J-Gras/bro-fuzzy-hashing

To install uncompiled plugins, Bro's source code must be available to the package manager (see package manager's [documentation](http://bro-package-manager.readthedocs.io/en/stable/quickstart.html#basic-configuration) for more information).

### Manual Install

The following will compile and install the Fuzzy Hashing plugin alongside Bro, assuming it can find the required libraries in a standard location:

	# ./configure && make && make install

If the headers are installed somewhere non-standard, you can point `configure` to the proper location passing the following options:

	--with-ssdeep=<ssdeep-include-directory>
	--with-tlsh=<tlsh-include-directory>

If everything built and installed correctly, you should see this:

	# bro -NN JGras::FuzzyHashing
	JGras::FuzzyHashing - Fuzzy hashing support for Bro (dynamic, version 0.3)
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

The plugin provides opaque values for each algorithm as well as file analyzers, following standard Bro conventions. For examples see the test cases in `tests/scripts`.
