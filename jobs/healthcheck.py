from __future__ import annotations

import sys

from jobs.config import get_job_settings
from jobs.queue import QueueUnavailable, RedisJobQueue


def main() -> int:
    settings = get_job_settings()
    if not settings.enabled:
        return 0
    try:
        return 0 if RedisJobQueue(settings).ping() else 1
    except QueueUnavailable:
        return 1


if __name__ == "__main__":
    sys.exit(main())
