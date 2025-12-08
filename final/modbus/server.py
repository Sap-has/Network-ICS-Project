#!/usr/bin/env python3
"""
Async Modbus TCP Test Server \u2014 Compatible with pymodbus 3.11.4
Simulates 3 PLCs using unit IDs 100, 101, 102.
"""

import asyncio
import logging
import json
from pathlib import Path

from pymodbus.server import (
    StartAsyncTcpServer,
)
from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusServerContext,
    ModbusSequentialDataBlock,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("modbus_test_server")


def build_device_context():
    """
    Create a PLC device context with DI, CO, HR, IR.
    """
    # Holding Registers (5000 entries)
    hr = [0] * 5000

    # Sample starting values
    hr[0] = 20
    hr[1] = 30
    hr[2] = 10

    return ModbusDeviceContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, hr),
        ir=ModbusSequentialDataBlock(0, [0] * 100),
    )


def build_server_context():
    """
    Map 3 PLCs to unit IDs:
      100 \u2192 PLC1
      101 \u2192 PLC2
      102 \u2192 PLC3
    """

    slaves = {
        100: build_device_context(),
        101: build_device_context(),
        102: build_device_context(),
    }

    # IMPORTANT: positional args only
    return ModbusServerContext(slaves, False)


async def main_async():
    # Load loopback config if present
    host = "127.0.0.1"
    port = 1502  # non-root safe

    path = Path("process_model.json")

    if path.exists():
        cfg = json.load(open(path))
        lb = cfg.get("loopback_mapping", {})
        host = lb.get("loopback_ip", "127.0.0.1")
        port = lb.get("base_port", 1502)

    context = build_server_context()

    logger.info(f"Starting ASYNC Modbus TCP server on {host}:{port} (pymodbus 3.11.4)")
    logger.info("Simulated PLC unit IDs: 100, 101, 102")

    await StartAsyncTcpServer(
        context=context,
        address=(host, port),
    )


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
