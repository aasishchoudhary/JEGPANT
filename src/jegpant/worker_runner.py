"""Command-line runner for asynchronous cognitive investigation jobs."""

from __future__ import annotations

import argparse
import logging
import signal
import time
from threading import Event

from .inference import OpenAICompatibleClient
from .runtime import CognitiveRuntime
from .service_factory import build_services
from .worker import AnalysisWorker


LOGGER = logging.getLogger("jegpant.worker")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the JEGPANT analysis worker.")
    parser.add_argument("--once", action="store_true", help="Process at most one job.")
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=2.0,
        help="Seconds to sleep after an idle poll (default: 2).",
    )
    parser.add_argument(
        "--worker-id",
        default=None,
        help="Stable worker label for audit/status purposes (generated if omitted).",
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=900,
        help="Job lease duration (30-86400 seconds).",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    if args.poll_seconds < 0.2 or args.poll_seconds > 60:
        raise SystemExit("--poll-seconds must be between 0.2 and 60")
    if not 30 <= args.lease_seconds <= 86400:
        raise SystemExit("--lease-seconds must be between 30 and 86400")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    services = build_services()
    client = OpenAICompatibleClient.from_environment()
    runtime = CognitiveRuntime(client)
    worker = AnalysisWorker(
        queue=services.jobs,
        case_store=services.cases,
        runtime=runtime,
        worker_id=args.worker_id,
        lease_seconds=args.lease_seconds,
    )

    stop = Event()

    def request_stop(signum, frame):
        del signum, frame
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    LOGGER.info("worker started id=%s instance=%s", worker.worker_id, services.instance_id)
    try:
        while not stop.is_set():
            outcome = worker.process_one()
            if outcome.status == "idle":
                if args.once:
                    break
                stop.wait(args.poll_seconds)
                continue

            LOGGER.info(
                "job processed id=%s status=%s result=%s error=%s",
                outcome.job_id,
                outcome.status,
                outcome.result_id,
                outcome.error_code,
            )
            if args.once:
                break
    finally:
        services.memory_store.close()
        LOGGER.info("worker stopped id=%s", worker.worker_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
