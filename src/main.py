import pymsrc
import json
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    --year : Year of the patch tuesday \n
    --month : Month of the patch tuesday \n
    !!! The day will be calculated automatically !!!
    """
    )
    parser.add_argument('--year', type=int, help="Year of the patch tuesday")
    parser.add_argument('--month', type=int, help="Month of the patch tuesday")
    args = parser.parse_args()

    if args.year and args.month:
        msrc = pymsrc.msrc(year=args.year, month=args.month)
    else:
        msrc = pymsrc.msrc()

    vulnerabilities = msrc.get_vulnerabilities()
    patch_tuesday_vulnerabilities = msrc.filter_patch_tuesday_vulnerabilities(vulnerabilities)
    msrc.vulnerabilities_to_json(patch_tuesday_vulnerabilities, 'patch_tuesday')
    msrc.vulnerabilities_to_excel(vulnerabilities, 'patch_tuesday')
