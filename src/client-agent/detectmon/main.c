#include "detect.h"
#include "rule.h"

int main()
{
    detect_init();
    detect_update(STATURS_HRE, NULL);
    agent_detect_state_t state = detect_get_state();
    assert(state.state == STATURS_HRE);
    assert(state.hre == NULL);
    assert(state.last_detection != 0);
    return 0;
}