
#ifndef BRO_PLUGIN_JGRAS_FUZZYHASHING
#define BRO_PLUGIN_JGRAS_FUZZYHASHING

#include <plugin/Plugin.h>

namespace plugin {
namespace JGras_FuzzyHashing {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
