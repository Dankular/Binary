#include "compass/core/backend.hpp"

namespace compass::core {

std::unique_ptr<IAnalysisBackend> makeDefaultAnalysisBackend() {
#ifdef COMPASS_HAVE_RIZIN
    return makeRizinBackend();
#else
    return makeRadare2Backend();
#endif
}

} // namespace compass::core
