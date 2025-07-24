import os
import json
import time
from simple_term_menu import TerminalMenu
from dotenv import load_dotenv
from openai import OpenAI
import fade

from modules.google_dorks_standalone import analyze as run_google_dorks
from modules.url2ioc import process_links_from_csv, generate_summary_and_stix_report

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DOTENV_PATH = '.env' 
ANALYZERS_DIR = os.path.join(SCRIPT_DIR, "analyzers")
ANALYSIS_DIR = os.path.join(SCRIPT_DIR, "analysis")
BANNER_FILE = os.path.join(SCRIPT_DIR, "res/banner.txt")
BANNER_FILE2 = os.path.join(SCRIPT_DIR, "res/banner2.txt")

load_dotenv(dotenv_path=DOTENV_PATH)
try:
    client = OpenAI()
    if not client.api_key: raise ValueError("API Key is empty.")
except Exception as e:
    print(f"[!] FATAL: Could not initialize OpenAI client. Error: {e}")
    exit()

def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    try:
        with open(BANNER_FILE, 'r') as f:
            print(fade.purpleblue(f.read()).strip())
        with open(BANNER_FILE2, 'r') as f:
            print(fade.pinkred(f.read()).strip())
    except FileNotFoundError:
        print("="*80)
        print("DORK2IOC Threat Intelligence Orchestrator".center(80))
        print("="*80)

def create_new_dorks_file():
    display_banner()
    print(fade.brazil("[+] Create New Dorks File"))
    try:
        topic = input("Enter the central topic for your dork search (e.g., 'Log4j vulnerability', 'Exposed RDP servers'): ")
        filename = input(f"Enter a filename for the new dorks file (e.g., 'log4j.json'): ")
        if not filename.endswith('.json'):
            filename += '.json'
        
        output_path = os.path.join(ANALYZERS_DIR, filename)

        prompt = f"""
        You are a world-class threat intelligence dorking expert.
        Generate a comprehensive list of Google dorks for finding information, vulnerabilities, and indicators related to the topic: "{topic}".
        Your response MUST be a single, minified JSON object with no markdown.
        The JSON structure must match this exact format, including all key names like 'google_dorks', 'social_media_dorks', etc.
        Use the placeholders `{{domain}}` and `{{domain_no_tld}}` where a specific target domain might be useful.

        Example Format:
        {{
          "google_dorks": [{{ "name": "Generic Vulnerability Search", "dork": "intitle:\"index of\" {topic}" }}],
          "social_media_dorks": [{{ "name": "Twitter Mentions", "dork": "site:twitter.com {topic} (ioc OR exploit)" }}],
          "metadata_dorks": [{{ "name": "Exposed Documents", "dork": "filetype:pdf {topic} author" }}],
          "linkedin_search_dorks": [{{ "name": "LinkedIn Professionals", "dork": "site:linkedin.com/in/ {topic} ciso" }}]
        }}
        """

        print("\n[*] Sending request to OpenAI to generate dorks... (This may take a moment)")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            response_format={"type": "json_object"}
        )
        dorks_json_str = response.choices[0].message.content
        
        os.makedirs(ANALYZERS_DIR, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(json.loads(dorks_json_str), f, indent=2)
        
        print(f"\n[+] Successfully created dorks file: {output_path}")
        time.sleep(3)
        return output_path

    except Exception as e:
        print(f"\n[!] An error occurred during dork generation: {e}")
        time.sleep(4)
        return None


def run_dorking_phase():
    display_banner()
    dorks_file_path = None
    
    os.makedirs(ANALYZERS_DIR, exist_ok=True)
    dork_files = [f for f in os.listdir(ANALYZERS_DIR) if f.endswith('.json')]
    menu_items = dork_files + ["[ Create New Dorks File ]"]
    
    terminal_menu = TerminalMenu(menu_items, title="Select a Google Dorks file or create a new one")
    chosen_index = terminal_menu.show()
    
    if chosen_index is None:
        print("[!] No selection made. Returning to main menu.")
        time.sleep(2)
        return

    chosen_item = menu_items[chosen_index]
    if chosen_item == "[ Create New Dorks File ]":
        dorks_file_path = create_new_dorks_file()
    else:
        dorks_file_path = os.path.join(ANALYZERS_DIR, chosen_item)

    if not dorks_file_path:
        return 

    display_banner()
    action_menu = TerminalMenu(["[ Begin Search ]"], title=f"Using Dorks File: {os.path.basename(dorks_file_path)}")
    if action_menu.show() == 0:
        print(fade.brazil("[*] Kicking off Google Dorks script..."))
        os.makedirs(ANALYSIS_DIR, exist_ok=True)
        output_file = run_google_dorks(dorks_file_path=dorks_file_path, results_dir=ANALYSIS_DIR)
        
        if output_file:
            print(fade.brazil(f"\n[+] Dorking complete! Please review the output file:"))
            print(fade.fire(f"   {output_file}"))
    else:
        print("[!] Search cancelled. Returning to main menu.")
    
    input(fade.pinkred("\nPress Enter to return to the main menu..."))


def run_analysis_phase():
    display_banner()
    print(fade.greenblue("[+] Loot Generator"))
    print(fade.greenblue("[*] This will process the output from the dorking phase to extract IOCs."))
    
    dork_results_file = os.path.join(ANALYSIS_DIR, "global_google_dorks_analysis.csv")
    detailed_csv_output = os.path.join(ANALYSIS_DIR, "detailed_ioc_report_defanged.csv")
    summary_csv_output = os.path.join(ANALYSIS_DIR, "technical_summary_report_defanged.csv")
    stix_output_file = os.path.join(ANALYSIS_DIR, "stix_threat_report.json")
    
    if not os.path.exists(dork_results_file):
        print(f"\n[!] Input file not found: {dork_results_file}")
        print("[!] Please run the 'Dorking Phase' first to generate results.")
        time.sleep(4)
        return

    action_menu = TerminalMenu(["[ Start Analysis ]"], title=f"Analyze results from: {os.path.basename(dork_results_file)}")
    if action_menu.show() == 0:
        print("\n[*] Kicking off url2ioc script...")
        
        aggregated_iocs = process_links_from_csv(dork_results_file, detailed_csv_output)
        
        if any(aggregated_iocs.values()):
            generate_summary_and_stix_report(aggregated_iocs, summary_csv_output, stix_output_file)
            print(fade.brazil("[+] Loot generation complete! Please review the output files:"))
            print(fade.greenblue(f"  - Detailed IOCs: {detailed_csv_output}"))
            print(fade.greenblue(f"  - Summary Report: {summary_csv_output}"))
            print(fade.greenblue(f"  - STIX Report: {stix_output_file}"))
        else:
            print("\n[!] No IOCs were collected. No summary reports were generated.")
    else:
        print("[!] Analysis cancelled. Returning to main menu.")

    input(fade.pinkred("Press Enter to return to the main menu..."))


def main():
    while True:
        display_banner()
        main_menu_items = [
            "1. Panning Phase (Select/Create Dorks & Search)",
            "2. Handling Phase (Generate Loot from Dork Results)",
            "3. Exit"
        ]
        terminal_menu = TerminalMenu(main_menu_items, title="  ...:: [ 𝗣 𝗔 𝗡 𝗛 𝗔 𝗡 𝗗 𝗟 𝗥 | 𝗠 𝗘 𝗡 𝗨 ] ::...\n..+===========================================+..")
        choice = terminal_menu.show()

        if choice == 0:
            run_dorking_phase()
        elif choice == 1:
            run_analysis_phase()
        elif choice == 2 or choice is None:
            print("Exiting.")
            break

if __name__ == "__main__":
    main()