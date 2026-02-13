"""Click CLI with Rich output."""

from __future__ import annotations

import json as json_lib

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .database import get_stats, init_db, list_groups
from .search import lookup_ip

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(version=__version__)
def cli():
    """ransomwatch — Check IPs against CISA #StopRansomware advisories."""
    init_db()


@cli.command()
@click.argument("ip")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def check(ip: str, as_json: bool):
    """Look up an IP address (supports defanged format like 192[.]168[.]1[.]1)."""
    result = lookup_ip(ip)

    if as_json:
        data = {
            "query": result.query,
            "normalized_ip": result.normalized_ip,
            "found": result.found,
            "matches": [
                {
                    "advisory_id": m.advisory_id,
                    "title": m.title,
                    "url": m.url,
                    "source": m.source,
                    "published": m.published.isoformat() if m.published else None,
                }
                for m in result.matches
            ],
        }
        click.echo(json_lib.dumps(data, indent=2))
        return

    if result.query != result.normalized_ip:
        console.print(
            f"[dim]Normalized:[/dim] {result.query} -> {result.normalized_ip}"
        )

    if not result.found:
        console.print(
            f"[green]No matches found[/green] for [bold]{result.normalized_ip}[/bold] "
            "in CISA #StopRansomware advisories."
        )
        return

    console.print(
        f"[red bold]MATCH FOUND[/red bold] — "
        f"[bold]{result.normalized_ip}[/bold] appears in "
        f"{len(result.matches)} advisory(ies):\n"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Advisory ID")
    table.add_column("Title")
    table.add_column("Source")
    table.add_column("Published")
    table.add_column("URL")

    for m in result.matches:
        table.add_row(
            m.advisory_id,
            m.title,
            m.source,
            m.published.strftime("%Y-%m-%d") if m.published else "—",
            m.url,
        )

    console.print(table)


@cli.command()
@click.option(
    "--include-pdfs", is_flag=True, help="Also parse PDF advisories for IOCs."
)
@click.option(
    "--discover",
    is_flag=True,
    help="Scrape CISA listing pages to discover new advisories beyond the built-in catalog.",
)
def update(include_pdfs: bool, discover: bool):
    """Download CISA advisories and populate the local database."""
    from rich.progress import Progress

    from .database import clear_iocs_for_advisory, insert_iocs, upsert_advisory
    from .pdf_parser import parse_pdf_file
    from .scraper import (
        discover_advisories,
        download_pdf,
        download_stix,
        enrich_advisory,
    )
    from .stix_parser import parse_stix_file

    with Progress(console=console) as progress:
        label = (
            "Discovering advisories (live)..."
            if discover
            else "Discovering advisories..."
        )
        task = progress.add_task(label, total=None)

        def on_progress(msg: str):
            progress.update(task, description=msg)

        advisories = discover_advisories(
            refresh=discover, progress_callback=on_progress
        )
        progress.update(task, description=f"Found {len(advisories)} advisories")
        progress.update(task, completed=True)

        if not advisories:
            console.print("[yellow]No #StopRansomware advisories found.[/yellow]")
            return

        enrich_task = progress.add_task(
            "Enriching advisories...", total=len(advisories)
        )

        total_iocs = 0
        for adv in advisories:
            progress.update(
                enrich_task,
                description=f"Processing {adv.advisory_id}...",
            )

            adv = enrich_advisory(adv)
            upsert_advisory(adv)

            # Download and parse STIX
            stix_path = download_stix(adv)
            if stix_path:
                clear_iocs_for_advisory(adv.advisory_id, source="stix")
                records = parse_stix_file(stix_path, adv.advisory_id)
                total_iocs += insert_iocs(records)

            # Optionally download and parse PDFs
            if include_pdfs:
                pdf_path = download_pdf(adv)
                if pdf_path:
                    clear_iocs_for_advisory(adv.advisory_id, source="pdf")
                    records = parse_pdf_file(pdf_path, adv.advisory_id)
                    total_iocs += insert_iocs(records)

            progress.advance(enrich_task)

    console.print(
        f"\n[green]Done![/green] Processed {len(advisories)} advisories, "
        f"stored {total_iocs} IOCs."
    )


@cli.command()
def stats():
    """Show database statistics."""
    data = get_stats()

    if data["advisories"] == 0:
        console.print(
            "[yellow]Database is empty. Run 'ransomwatch update' first.[/yellow]"
        )
        return

    table = Table(title="Database Statistics", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Advisories", str(data["advisories"]))
    table.add_row("Total IOCs", str(data["total_iocs"]))

    if data["by_type"]:
        table.add_section()
        for ioc_type, count in sorted(data["by_type"].items()):
            table.add_row(f"  {ioc_type}", str(count))

    if data["by_source"]:
        table.add_section()
        for source, count in sorted(data["by_source"].items()):
            table.add_row(f"  Source: {source}", str(count))

    console.print(table)


@cli.command("list-groups")
def list_groups_cmd():
    """List known ransomware groups from advisories."""
    groups = list_groups()

    if not groups:
        console.print(
            "[yellow]No groups found. Run 'ransomwatch update' first.[/yellow]"
        )
        return

    table = Table(title="Ransomware Groups", show_header=True, header_style="bold")
    table.add_column("Group / Campaign")
    table.add_column("Advisory ID")

    for name, adv_id in groups:
        table.add_row(name, adv_id)

    console.print(table)
