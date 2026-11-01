"""Interfaz de línea de comandos."""

import argparse
import asyncio
import json
import sys

from rich.console import Console

from kyros import __version__
from kyros.config import load_config
from kyros.output import render, write_json
from kyros.runner import scan
from kyros.validate import split_email


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kyros",
        description="OSINT automatizado para correos electrónicos.",
    )
    parser.add_argument("email", help="Correo a investigar")
    parser.add_argument("-c", "--config", help="Ruta al YAML con las API keys")
    parser.add_argument("-o", "--output", help="Guardar el informe en un archivo JSON")
    parser.add_argument("-t", "--timeout", type=float, default=15.0, help="Segundos por servicio")
    parser.add_argument("--json", action="store_true", help="Imprimir JSON en lugar de la tabla")
    parser.add_argument("-V", "--version", action="version", version=f"kyros {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(stderr=True)

    try:
        split_email(args.email)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    try:
        keys = load_config(args.config)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    report = asyncio.run(scan(args.email, keys, timeout=args.timeout))

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        render(report, Console())

    if args.output:
        write_json(report, args.output)
        console.print(f"Informe guardado en {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
