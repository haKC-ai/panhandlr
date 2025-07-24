import os
import time
import json
import csv
from dotenv import load_dotenv
from googleapiclient.discovery import build
import fade
load_dotenv(dotenv_path=".env")

BASE_DIR = ""
DEFAULT_RESULTS_DIR = os.path.join(BASE_DIR, "analysis")

def load_dorks(dorks_file_path, domain=None):
    try:
        with open(dorks_file_path, "r") as f:
            dorks_data = json.load(f).get("google_dorks", [])

        if not dorks_data:
            print(f"[!] No dorks found under the 'google_dorks' key in {dorks_file_path}")
            return []

        if domain:
            domain_no_tld = domain.split(".")[0]
            for item in dorks_data:
                item["dork"] = item["dork"].format(domain=domain, domain_no_tld=domain_no_tld)
        else:
            for item in dorks_data:
                item["dork"] = item["dork"].format(domain="", domain_no_tld="")

        return dorks_data

    except FileNotFoundError:
        print(f"[!] Dorks file not found at: {dorks_file_path}")
        return []
    except Exception as e:
        print(f"[!] Failed to load or parse dorks file: {e}")
        return []

def analyze(dorks_file_path, domain=None, results_dir=DEFAULT_RESULTS_DIR):
    os.makedirs(results_dir, exist_ok=True)
    output_file = os.path.join(
        results_dir,
        f"{domain}_google_dorks_analysis.csv" if domain else "global_google_dorks_analysis.csv"
    )

    api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
    cse_id = os.getenv("GOOGLE_CSE_ID")

    if not api_key or not cse_id:
        msg = "[!] GOOGLE_SEARCH_API_KEY or GOOGLE_CSE_ID not set in .env"
        print(msg)
        return

    dorks = load_dorks(dorks_file_path, domain)
    if not dorks:
        msg = "[!] No dorks loaded. Skipping execution."
        print(msg)
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["dork", "title", "dork_url"])
        return output_file


    all_findings = []
    seen_links = set()

    try:
        service = build("customsearch", "v1", developerKey=api_key)

        for dork_item in dorks:
            dork_name = dork_item["name"]
            dork_query = dork_item["dork"]

            print(f"[+] Executing dork: {dork_name}")
            try:
                # Using num=10 to get up to 10 results per dork
                res = service.cse().list(q=dork_query, cx=cse_id, num=10).execute()
                items = res.get("items", [])

                if items:
                    for item in items:
                        link = item.get('link')
                        if link and link not in seen_links:
                            seen_links.add(link)
                            all_findings.append([
                                dork_name,
                                item.get('title', 'N/A'),
                                link
                            ])

                time.sleep(1.5)

            except Exception as query_error:
                print(f"[!] Error running query '{dork_name}': {query_error}")

    except Exception as api_error:
        print(f"[!] Critical API error: {api_error}")

    if all_findings:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["dork", "title", "dork_url"])
            writer.writerows(all_findings)
        print(fade.brazil(f"[+] Analysis complete. {len(all_findings)} unique results saved to {output_file}"))
    else:
        print("[+] No results found. Either good hygiene or API misconfiguration.")
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["dork", "title", "dork_url"])
    
    return output_file


if __name__ == "__main__":
    print(fade.brazil("[*] Running google_dorks_standalone.py in standalone mode."))
    default_dork_file = os.path.join("analyzers", "sharepoint.json")
    if os.path.exists(default_dork_file):
        analyze(dorks_file_path=default_dork_file)
    else:
        print(f"[!] Default dork file not found at '{default_dork_file}'. Cannot run in standalone mode.")