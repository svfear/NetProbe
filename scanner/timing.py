from dataclasses import dataclass
from typing import Dict, Optional

@dataclass(frozen=True)
class TimingProfile:
    level: int
    name: str
    max_parallel: int
    min_timeout: float
    max_timeout: float
    initial_timeout: float
    host_delay: float
TIMING_PROFILES: Dict[int, TimingProfile] = {0: TimingProfile(level=0, name='paranoid', max_parallel=1, min_timeout=5.0, max_timeout=15.0, initial_timeout=15.0, host_delay=300.0), 1: TimingProfile(level=1, name='sneaky', max_parallel=5, min_timeout=5.0, max_timeout=10.0, initial_timeout=10.0, host_delay=15.0), 2: TimingProfile(level=2, name='polite', max_parallel=25, min_timeout=3.0, max_timeout=5.0, initial_timeout=5.0, host_delay=0.4), 3: TimingProfile(level=3, name='normal', max_parallel=100, min_timeout=0.5, max_timeout=3.0, initial_timeout=1.5, host_delay=0.0), 4: TimingProfile(level=4, name='aggressive', max_parallel=500, min_timeout=0.1, max_timeout=1.2, initial_timeout=0.5, host_delay=0.0), 5: TimingProfile(level=5, name='insane', max_parallel=1500, min_timeout=0.05, max_timeout=0.5, initial_timeout=0.3, host_delay=0.0)}

class AdaptiveTiming:

    def __init__(self, profile: TimingProfile):
        self.profile = profile
        self.srtt: float = profile.initial_timeout
        self.rttvar: float = profile.initial_timeout / 2.0
        self.timeout: float = profile.initial_timeout
        self.alpha: float = 0.125
        self.beta: float = 0.25

    def update_rtt(self, sample_rtt: float) -> float:
        if self.srtt == self.profile.initial_timeout:
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * abs(self.srtt - sample_rtt)
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * sample_rtt
        calculated = self.srtt + 4 * self.rttvar
        self.timeout = max(self.profile.min_timeout, min(calculated, self.profile.max_timeout))
        return self.timeout

    def get_timeout(self) -> float:
        return self.timeout
