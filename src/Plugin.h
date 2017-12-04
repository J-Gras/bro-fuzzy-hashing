
#ifndef BRO_PLUGIN_JGRAS_SSDEEP
#define BRO_PLUGIN_JGRAS_SSDEEP

#include <plugin/Plugin.h>

namespace plugin {
namespace JGras_SSDeep {

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
