"""Small offline CSV report used only as the v0.9 demo workspace."""

import argparse
import csv
from decimal import Decimal
from pathlib import Path


def total_revenue(path):
    with Path(path).open(newline="", encoding="utf-8") as stream:
        return sum(
            (Decimal(row["amount"]) for row in csv.DictReader(stream)
             if row["status"] == "paid"),
            Decimal("0"),
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    print(f"Total: {total_revenue(args.input):.2f}")


if __name__ == "__main__":
    main()
