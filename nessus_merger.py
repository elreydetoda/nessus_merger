#!/usr/bin/python3

# derived from https://gist.github.com/mastahyeti/2720173
# Extended to allow a custom directory to be specified via command line argument.

import xml.etree.ElementTree as etree
import shutil, os, sys, getopt
from argparse import ArgumentParser
from pathlib import Path


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
    dirz = args.direcotry
    print(f"Searching for .nessus files to merge in directory: {dirz}")

    ### Starting important stuff

    first_file_parsed = True
    for file_name in os.listdir(dirz):
        if ".nessus" in file_name:
            print("Parsing - " + dirz + file_name)
            if first_file_parsed:
                mainTree = etree.parse(dirz + file_name)
                report = mainTree.find("Report")
                report.attrib["name"] = "Merged Report"
                first_file_parsed = False
            else:
                tree = etree.parse(dirz + file_name)
                for host in tree.findall(".//ReportHost"):
                    existing_host = report.find(
                        ".//ReportHost[@name='" + host.attrib["name"] + "']"
                    )
                    if not existing_host:
                        print("adding host: " + host.attrib["name"])
                        report.append(host)
                    else:
                        for item in host.findall("ReportItem"):
                            if not existing_host.find(
                                "ReportItem[@port='"
                                + item.attrib["port"]
                                + "'][@pluginID='"
                                + item.attrib["pluginID"]
                                + "']"
                            ):
                                print(
                                    "adding finding: "
                                    + item.attrib["port"]
                                    + ":"
                                    + item.attrib["pluginID"]
                                )
                                existing_host.append(item)
    print(" => done.")

    if "nss_report" in os.listdir("."):
        shutil.rmtree("nss_report")

    os.mkdir("nss_report")
    mainTree.write("nss_report/report.nessus", encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    main()
