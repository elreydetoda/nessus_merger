#!/usr/bin/python3

# derived from https://gist.github.com/mastahyeti/2720173
# Extended to allow a custom directory to be specified via command line argument.

import xml.etree.ElementTree as etree
import shutil, os, sys, getopt
from argparse import ArgumentParser
from pathlib import Path


def find_elements(main_report: etree.Element, xpath_query: str) -> etree.Element:
    """
    searches current outputting report for items
    """
    return main_report.find(xpath_query)


def main():
    parser = ArgumentParser(
        """
      Used to merge multiple nessus files into one, which'll be placed in the nss_report folder
      """
    )
    parser.add_argument(
        "directory",
        type=Path,
        help="The directory which has all the .nessus files in it",
    )
    args = parser.parse_args()
    dirz: Path = args.directory
    output_report = Path("nss_report/report.nessus")
    print(f"Searching for .nessus files to merge in directory: {dirz}")

    ### Starting important stuff

    first_file_parsed = True
    for file_name in dirz.glob("*.nessus"):
        print(f"Parsing - {file_name}")
        if first_file_parsed:
            main_tree = etree.parse(file_name)
            report = main_tree.find("Report")
            report.attrib["name"] = "Merged Report"
            first_file_parsed = False
        else:
            tree = etree.parse(file_name)
            for host in tree.findall(".//ReportHost"):
                current_host = find_elements(
                    report,
                    f".//ReportHost[@name='{host.attrib['name']}']",
                )
                if current_host:
                    for item in host.findall("ReportItem"):
                        if find_elements(
                            current_host,
                            f"ReportItem[@port='{item.attrib['port']}'][@pluginID='{item.attrib['pluginID']}']",
                        ):
                            pass
                        else:
                            print(
                                f"adding finding: {item.attrib['port']}:{item.attrib['pluginID']}"
                            )
                            current_host.append(item)
                else:
                    print(f"adding host: {host.attrib['name']}")
                    report.append(host)
    print(" => done.")

    if output_report.exists():
        output_report.unlink()
    main_tree.write(output_report, encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    main()
